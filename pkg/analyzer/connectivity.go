package analyzer

import (
	"context"
	"fmt"
	"strings"

	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/istio-doctor/pkg/client"
	"github.com/istio-doctor/pkg/collector"
)

// TrafficHop represents a single hop in the traffic path.
type TrafficHop struct {
	Name        string
	Type        string // SOURCE, SIDECAR, INGRESS_GATEWAY, EGRESS_GATEWAY, EXTERNAL
	Status      string // PASS, WARN, FAIL, UNKNOWN
	Description string
	Issues      []HopIssue
	Resources   []string // Relevant resource names
}

// HopIssue is a problem found at a traffic hop.
type HopIssue struct {
	Severity    string
	Description string
	Remediation string
	Resource    string
}

// TraceResult holds the full traffic path analysis result.
type TraceResult struct {
	Source      string
	Destination string
	Protocol    string
	Hops        []TrafficHop
	Verdict     string // ALLOWED, BLOCKED, PARTIAL, UNKNOWN
	BlockedAt   string
	Summary     []string
}

// TraceRequest defines a traffic tracing request.
type TraceRequest struct {
	// Source pod reference: namespace/podname or namespace/app=label
	FromPod     string
	// Destination: namespace/service:port or external-host:port
	ToDestination string
	// HTTP specifics
	Path   string
	Method string
	// Whether this goes through egress gateway
	UseEgressGateway bool
	// Trust domain for SPIFFE URIs
	TrustDomain string
}

// ConnectivityAnalyzer traces and analyzes traffic paths.
type ConnectivityAnalyzer struct {
	client    *client.IstioClient
	policies  *collector.PolicyCollection
	authz     *AuthzAnalyzer
}

func NewConnectivityAnalyzer(c *client.IstioClient, policies *collector.PolicyCollection) *ConnectivityAnalyzer {
	return &ConnectivityAnalyzer{
		client:   c,
		policies: policies,
		authz:    NewAuthzAnalyzer("cluster.local"),
	}
}

// Trace performs end-to-end traffic path analysis.
func (ca *ConnectivityAnalyzer) Trace(ctx context.Context, req *TraceRequest) (*TraceResult, error) {
	result := &TraceResult{
		Source:      req.FromPod,
		Destination: req.ToDestination,
		Protocol:    req.Method,
	}

	// Resolve source pod
	sourcePod, err := ca.client.FindPodByName(ctx, req.FromPod)
	if err != nil {
		return nil, fmt.Errorf("resolve source pod: %w", err)
	}

	// Parse destination
	destNS, destSvc, destPort, isExternal := parseDestination(req.ToDestination)

	// Build traffic request context
	trafficReq := &TrafficRequest{
		SourceNamespace:      sourcePod.Namespace,
		SourceServiceAccount: sourcePod.Spec.ServiceAccountName,
		SourcePrincipal:      client.GetWorkloadIdentity(sourcePod),
		SourceIP:             sourcePod.Status.PodIP,
		DestNamespace:        destNS,
		DestService:          destSvc,
		DestPort:             destPort,
		DestPath:             req.Path,
		Method:               req.Method,
	}
	if trafficReq.Method == "" {
		trafficReq.Method = "GET"
	}

	// === HOP 1: Source Pod ===
	sourceHop := ca.analyzeSourcePod(sourcePod)
	result.Hops = append(result.Hops, sourceHop)

	if sourceHop.Status == "FAIL" {
		result.Verdict = "BLOCKED"
		result.BlockedAt = "Source Pod"
		result.Summary = append(result.Summary, "Traffic blocked at source: "+sourceHop.Issues[0].Description)
		return result, nil
	}

	// === HOP 2: Egress from source (NetworkPolicy, Sidecar CR) ===
	egressHop := ca.analyzeSourceEgress(ctx, sourcePod, req, trafficReq, isExternal)
	result.Hops = append(result.Hops, egressHop)

	if isExternal || req.UseEgressGateway {
		// === HOP 3: AuthZ to Egress Gateway ===
		egressGWHop := ca.analyzeEgressGatewayAuthz(ctx, trafficReq, destSvc)
		result.Hops = append(result.Hops, egressGWHop)

		// === HOP 4: Egress Gateway Configuration ===
		egressConfigHop := ca.analyzeEgressGatewayConfig(ctx, destSvc, destPort, isExternal)
		result.Hops = append(result.Hops, egressConfigHop)

		// === HOP 5: ServiceEntry / External ===
		externalHop := ca.analyzeExternalDestination(ctx, destSvc, destPort)
		result.Hops = append(result.Hops, externalHop)
	} else {
		// Internal service traffic
		// === HOP 3: AuthZ to destination (from ingress gateway or directly) ===
		destAuthzHop := ca.analyzeDestinationAuthz(ctx, trafficReq)
		result.Hops = append(result.Hops, destAuthzHop)

		// === HOP 4: Destination Service ===
		destHop := ca.analyzeDestinationService(ctx, destNS, destSvc, destPort)
		result.Hops = append(result.Hops, destHop)
	}

	// Compute overall verdict
	result.Verdict = ca.computeVerdict(result.Hops, &result.BlockedAt)
	result.Summary = ca.buildSummary(result)
	return result, nil
}

// analyzeSourcePod checks if the source pod is healthy and has a functioning sidecar.
func (ca *ConnectivityAnalyzer) analyzeSourcePod(pod *corev1.Pod) TrafficHop {
	hop := TrafficHop{
		Name: fmt.Sprintf("Source: %s/%s", pod.Namespace, pod.Name),
		Type: "SOURCE",
	}
	hop.Resources = append(hop.Resources, fmt.Sprintf("pod/%s", pod.Name))

	// Check sidecar injection
	if !client.IsSidecarInjected(pod) {
		hop.Status = "WARN"
		hop.Description = "Pod has no istio-proxy sidecar - traffic is not intercepted by the mesh"
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "WARN",
			Description: "No istio-proxy container found",
			Remediation: fmt.Sprintf("Label namespace '%s' with istio-injection=enabled and restart pod", pod.Namespace),
		})
		return hop
	}

	// Check pod running
	if pod.Status.Phase != corev1.PodRunning {
		hop.Status = "FAIL"
		hop.Description = fmt.Sprintf("Pod is not running (phase: %s)", pod.Status.Phase)
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "ERROR",
			Description: fmt.Sprintf("Pod phase: %s", pod.Status.Phase),
			Remediation: fmt.Sprintf("kubectl describe pod %s -n %s", pod.Name, pod.Namespace),
		})
		return hop
	}

	// Check sidecar container is ready
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == "istio-proxy" {
			if !cs.Ready {
				hop.Status = "WARN"
				hop.Issues = append(hop.Issues, HopIssue{
					Severity:    "WARN",
					Description: "istio-proxy container is not ready",
					Remediation: fmt.Sprintf("kubectl logs %s -n %s -c istio-proxy", pod.Name, pod.Namespace),
				})
			}
			if cs.RestartCount > 3 {
				hop.Issues = append(hop.Issues, HopIssue{
					Severity:    "WARN",
					Description: fmt.Sprintf("istio-proxy has restarted %d times - may be crashing", cs.RestartCount),
					Remediation: fmt.Sprintf("kubectl logs %s -n %s -c istio-proxy --previous", pod.Name, pod.Namespace),
				})
			}
		}
	}

	if hop.Status == "" {
		hop.Status = "PASS"
		hop.Description = fmt.Sprintf("Pod running, sidecar injected (identity: %s)", client.GetWorkloadIdentity(pod))
	}
	return hop
}

// analyzeSourceEgress checks NetworkPolicy, Sidecar CR egress restrictions.
func (ca *ConnectivityAnalyzer) analyzeSourceEgress(ctx context.Context, pod *corev1.Pod, req *TraceRequest, trafficReq *TrafficRequest, isExternal bool) TrafficHop {
	hop := TrafficHop{
		Name: "Source Egress",
		Type: "SIDECAR",
	}

	// Check Sidecar CR for egress restrictions
	sidecarCR := ca.policies.FindSidecarForWorkload(pod.Namespace, pod.Labels)
	if sidecarCR != nil {
		hop.Resources = append(hop.Resources, fmt.Sprintf("sidecar/%s", sidecarCR.Name))
		egressAllowed := ca.checkSidecarEgress(sidecarCR, req.ToDestination)
		if !egressAllowed {
			hop.Status = "FAIL"
			hop.Description = fmt.Sprintf("Sidecar CR '%s' restricts egress - destination not in egress hosts", sidecarCR.Name)
			hop.Issues = append(hop.Issues, HopIssue{
				Severity:    "ERROR",
				Description: fmt.Sprintf("Sidecar '%s/%s' does not allow egress to '%s'", sidecarCR.Namespace, sidecarCR.Name, req.ToDestination),
				Remediation: fmt.Sprintf("Add egress host to sidecar CR: kubectl edit sidecar %s -n %s", sidecarCR.Name, sidecarCR.Namespace),
				Resource:    fmt.Sprintf("sidecar/%s", sidecarCR.Name),
			})
			return hop
		}
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "INFO",
			Description: fmt.Sprintf("Sidecar CR '%s' applied - egress to destination is permitted", sidecarCR.Name),
		})
	}

	// Check NetworkPolicy for egress
	netpolIssues := ca.checkNetworkPolicyEgress(ctx, pod)
	hop.Issues = append(hop.Issues, netpolIssues...)

	if hop.Status == "" {
		hop.Status = "PASS"
		hop.Description = "No egress restrictions blocking this traffic"
	}
	return hop
}

func (ca *ConnectivityAnalyzer) checkSidecarEgress(sc *networkingv1alpha3.Sidecar, destination string) bool {
	for _, egress := range sc.Spec.Egress {
		for _, host := range egress.Hosts {
			// Host format: namespace/host or ./host or */host
			parts := strings.SplitN(host, "/", 2)
			hostPart := host
			if len(parts) == 2 {
				hostPart = parts[1]
			}
			if hostPart == "*" || strings.HasSuffix(destination, hostPart) || hostPart == destination {
				return true
			}
		}
	}
	// If no egress defined, defaults to allow all
	return len(sc.Spec.Egress) == 0
}

func (ca *ConnectivityAnalyzer) checkNetworkPolicyEgress(ctx context.Context, pod *corev1.Pod) []HopIssue {
	var issues []HopIssue

	for _, np := range ca.policies.NetworkPolicies {
		if np.Namespace != pod.Namespace {
			continue
		}
		// Check if this NetworkPolicy selects our pod
		if !labelsMatchNetPol(np.Spec.PodSelector.MatchLabels, pod.Labels) {
			continue
		}
		// If NetworkPolicy exists with egress rules, check it
		for _, pt := range np.Spec.PolicyTypes {
			if pt == "Egress" {
				if len(np.Spec.Egress) == 0 {
					issues = append(issues, HopIssue{
						Severity:    "ERROR",
						Description: fmt.Sprintf("NetworkPolicy '%s/%s' selects pod and restricts egress with no egress rules - all egress BLOCKED", np.Namespace, np.Name),
						Remediation: fmt.Sprintf("kubectl edit networkpolicy %s -n %s", np.Name, np.Namespace),
						Resource:    fmt.Sprintf("networkpolicy/%s", np.Name),
					})
				}
			}
		}
	}
	return issues
}

func (ca *ConnectivityAnalyzer) analyzeEgressGatewayAuthz(ctx context.Context, trafficReq *TrafficRequest, externalHost string) TrafficHop {
	hop := TrafficHop{
		Name: "AuthZ: Source → Egress Gateway",
		Type: "EGRESS_GATEWAY",
	}

	// Build a traffic request to the egress gateway
	egressReq := &TrafficRequest{
		SourceNamespace:      trafficReq.SourceNamespace,
		SourceServiceAccount: trafficReq.SourceServiceAccount,
		SourcePrincipal:      trafficReq.SourcePrincipal,
		DestNamespace:        "istio-system",
		DestService:          "istio-egressgateway",
		DestPort:             trafficReq.DestPort,
		DestPath:             trafficReq.DestPath,
		Method:               trafficReq.Method,
	}

	decision := ca.authz.Evaluate(egressReq, ca.policies.AuthorizationPolicies)

	if !decision.Allowed {
		hop.Status = "FAIL"
		hop.Description = fmt.Sprintf("Source not authorized to reach egress gateway: %s", decision.Reason)
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "ERROR",
			Description: decision.Reason,
			Remediation: fmt.Sprintf("Create AuthorizationPolicy in istio-system allowing principal '%s' to reach egress gateway port %d", trafficReq.SourcePrincipal, trafficReq.DestPort),
		})
	} else {
		hop.Status = "PASS"
		hop.Description = fmt.Sprintf("Authorized to reach egress gateway (%s)", decision.Reason)
		if decision.MatchedPolicy != "" {
			hop.Resources = append(hop.Resources, fmt.Sprintf("authorizationpolicy/%s", decision.MatchedPolicy))
		}
	}

	for _, w := range decision.Warnings {
		hop.Issues = append(hop.Issues, HopIssue{Severity: "WARN", Description: w})
	}

	return hop
}

func (ca *ConnectivityAnalyzer) analyzeEgressGatewayConfig(ctx context.Context, externalHost string, port uint32, isExternal bool) TrafficHop {
	hop := TrafficHop{
		Name: "Egress Gateway Configuration",
		Type: "EGRESS_GATEWAY",
	}

	// Check Gateway CR for external host
	gw := ca.policies.FindGatewayForHost(externalHost)
	if gw == nil {
		hop.Status = "FAIL"
		hop.Description = fmt.Sprintf("No Gateway CR found for host '%s'", externalHost)
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "ERROR",
			Description: fmt.Sprintf("No Gateway resource defines server for host '%s'", externalHost),
			Remediation: fmt.Sprintf("Create a Gateway CR in istio-system with server.hosts=[\"*/%s\"] and selector for egress gateway", externalHost),
		})
		return hop
	}
	hop.Resources = append(hop.Resources, fmt.Sprintf("gateway/%s/%s", gw.Namespace, gw.Name))

	// Check VirtualService routes traffic through egress gateway
	vss := ca.policies.FindVirtualServicesForGateway(gw.Namespace, gw.Name)
	if len(vss) == 0 {
		hop.Status = "FAIL"
		hop.Description = fmt.Sprintf("Gateway '%s' exists but no VirtualService routes through it", gw.Name)
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "ERROR",
			Description: "No VirtualService attached to this Gateway",
			Remediation: fmt.Sprintf("Create a VirtualService with gateways: [%s/%s] routing to external host", gw.Namespace, gw.Name),
		})
		return hop
	}

	// Check VirtualService has both mesh and gateway entries (required pattern for egress)
	for _, vs := range vss {
		hasMesh := false
		hasGW := false
		for _, gwRef := range vs.Spec.Gateways {
			if gwRef == "mesh" {
				hasMesh = true
			} else {
				hasGW = true
			}
		}
		if !hasMesh {
			hop.Issues = append(hop.Issues, HopIssue{
				Severity:    "WARN",
				Description: fmt.Sprintf("VirtualService '%s/%s' doesn't include 'mesh' in gateways - internal pods won't route through egress gateway", vs.Namespace, vs.Name),
				Remediation: fmt.Sprintf("Add 'mesh' to spec.gateways in VirtualService '%s'", vs.Name),
				Resource:    fmt.Sprintf("virtualservice/%s", vs.Name),
			})
		}
		_ = hasGW
		hop.Resources = append(hop.Resources, fmt.Sprintf("virtualservice/%s/%s", vs.Namespace, vs.Name))
	}

	// Check DestinationRule for TLS origination
	dr := ca.policies.FindDestinationRuleForHost(externalHost, "istio-system")
	if dr == nil {
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "WARN",
			Description: fmt.Sprintf("No DestinationRule found for '%s' - TLS origination mode unknown. Egress gateway may not be doing TLS origination", externalHost),
			Remediation: fmt.Sprintf("Create a DestinationRule for host '%s' with trafficPolicy.tls.mode=SIMPLE or MUTUAL if TLS is needed", externalHost),
		})
	} else {
		hop.Resources = append(hop.Resources, fmt.Sprintf("destinationrule/%s/%s", dr.Namespace, dr.Name))
		tlsMode := dr.Spec.GetTrafficPolicy().GetTls().GetMode().String()
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "INFO",
			Description: fmt.Sprintf("DestinationRule TLS mode: %s", tlsMode),
		})
	}

	if hop.Status == "" {
		hop.Status = "PASS"
		hop.Description = fmt.Sprintf("Egress gateway config OK (Gateway: %s, VirtualServices: %d)", gw.Name, len(vss))
	}
	return hop
}

func (ca *ConnectivityAnalyzer) analyzeExternalDestination(ctx context.Context, host string, port uint32) TrafficHop {
	hop := TrafficHop{
		Name: fmt.Sprintf("External: %s:%d", host, port),
		Type: "EXTERNAL",
	}

	// Check ServiceEntry exists
	se := ca.policies.FindServiceEntryForHost(host)
	if se == nil {
		hop.Status = "FAIL"
		hop.Description = fmt.Sprintf("No ServiceEntry for external host '%s'", host)
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "ERROR",
			Description: fmt.Sprintf("External host '%s' not registered in the mesh", host),
			Remediation: fmt.Sprintf("Create a ServiceEntry for host '%s' with the correct port and resolution mode", host),
		})
		return hop
	}

	hop.Resources = append(hop.Resources, fmt.Sprintf("serviceentry/%s/%s", se.Namespace, se.Name))

	// Validate ServiceEntry port matches
	portFound := false
	for _, p := range se.Spec.Ports {
		if p.Number == uint32(port) {
			portFound = true
			break
		}
	}
	if !portFound {
		hop.Status = "WARN"
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "ERROR",
			Description: fmt.Sprintf("ServiceEntry '%s' doesn't include port %d", se.Name, port),
			Remediation: fmt.Sprintf("Add port %d to ServiceEntry '%s'", port, se.Name),
		})
		return hop
	}

	hop.Status = "PASS"
	hop.Description = fmt.Sprintf("ServiceEntry '%s' registered for host with port %d", se.Name, port)
	return hop
}

func (ca *ConnectivityAnalyzer) analyzeDestinationAuthz(ctx context.Context, trafficReq *TrafficRequest) TrafficHop {
	hop := TrafficHop{
		Name: fmt.Sprintf("AuthZ: → %s/%s:%d", trafficReq.DestNamespace, trafficReq.DestService, trafficReq.DestPort),
		Type: "SIDECAR",
	}

	decision := ca.authz.Evaluate(trafficReq, ca.policies.AuthorizationPolicies)

	if !decision.Allowed {
		hop.Status = "FAIL"
		hop.Description = fmt.Sprintf("Traffic not authorized: %s", decision.Reason)
		for _, dm := range decision.DenyPolicies {
			hop.Issues = append(hop.Issues, HopIssue{
				Severity:    "ERROR",
				Description: fmt.Sprintf("Blocked by DENY policy: %s/%s (rule[%d]): %s", dm.PolicyNamespace, dm.PolicyName, dm.RuleIndex, dm.MatchReason),
				Resource:    fmt.Sprintf("authorizationpolicy/%s/%s", dm.PolicyNamespace, dm.PolicyName),
				Remediation: fmt.Sprintf("kubectl get authorizationpolicy %s -n %s -o yaml", dm.PolicyName, dm.PolicyNamespace),
			})
		}
		if len(decision.DenyPolicies) == 0 {
			hop.Issues = append(hop.Issues, HopIssue{
				Severity:    "ERROR",
				Description: decision.Reason,
				Remediation: fmt.Sprintf("Create an AuthorizationPolicy in namespace '%s' allowing principal '%s'", trafficReq.DestNamespace, trafficReq.SourcePrincipal),
			})
		}
	} else {
		hop.Status = "PASS"
		hop.Description = fmt.Sprintf("Authorized (%s)", decision.Reason)
		if decision.MatchedPolicy != "" {
			hop.Resources = append(hop.Resources, fmt.Sprintf("authorizationpolicy/%s", decision.MatchedPolicy))
		}
	}

	for _, w := range decision.Warnings {
		hop.Issues = append(hop.Issues, HopIssue{Severity: "WARN", Description: w})
	}

	return hop
}

func (ca *ConnectivityAnalyzer) analyzeDestinationService(ctx context.Context, ns, svcName string, port uint32) TrafficHop {
	hop := TrafficHop{
		Name: fmt.Sprintf("Destination: %s/%s", ns, svcName),
		Type: "SOURCE",
	}

	// Check service exists
	svc, err := ca.client.K8s.CoreV1().Services(ns).Get(ctx, svcName, metav1.GetOptions{})
	if err != nil {
		hop.Status = "FAIL"
		hop.Description = fmt.Sprintf("Service '%s/%s' not found", ns, svcName)
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "ERROR",
			Description: fmt.Sprintf("kubectl get svc %s -n %s returned not found", svcName, ns),
			Remediation: "Verify service name and namespace are correct",
		})
		return hop
	}
	hop.Resources = append(hop.Resources, fmt.Sprintf("service/%s/%s", ns, svcName))

	// Check port exists and has correct name (Istio requires named ports for protocol detection)
	portFound := false
	for _, sp := range svc.Spec.Ports {
		if sp.Port == int32(port) {
			portFound = true
			if sp.Name == "" {
				hop.Issues = append(hop.Issues, HopIssue{
					Severity:    "WARN",
					Description: fmt.Sprintf("Service port %d has no name - Istio uses port names for protocol detection (e.g. 'http', 'grpc', 'tcp')", port),
					Remediation: fmt.Sprintf("kubectl patch svc %s -n %s --type=json -p '[{\"op\":\"replace\",\"path\":\"/spec/ports/0/name\",\"value\":\"http\"}]'", svcName, ns),
				})
			} else if !validPortName(sp.Name) {
				hop.Issues = append(hop.Issues, HopIssue{
					Severity:    "WARN",
					Description: fmt.Sprintf("Service port name '%s' may not be recognized by Istio for protocol detection. Use http, https, grpc, tcp, etc.", sp.Name),
					Resource:    fmt.Sprintf("service/%s", svcName),
				})
			}
		}
	}

	if !portFound {
		hop.Status = "FAIL"
		hop.Description = fmt.Sprintf("Port %d not defined in service '%s'", port, svcName)
		hop.Issues = append(hop.Issues, HopIssue{
			Severity:    "ERROR",
			Description: fmt.Sprintf("Service has no port %d", port),
			Remediation: fmt.Sprintf("Add port %d to service spec or check if you're using the correct port", port),
		})
		return hop
	}

	// Check endpoints exist
	endpoints, err := ca.client.K8s.CoreV1().Endpoints(ns).Get(ctx, svcName, metav1.GetOptions{})
	if err == nil {
		readyCount := 0
		for _, subset := range endpoints.Subsets {
			readyCount += len(subset.Addresses)
		}
		if readyCount == 0 {
			hop.Status = "WARN"
			hop.Issues = append(hop.Issues, HopIssue{
				Severity:    "ERROR",
				Description: fmt.Sprintf("Service '%s' has no ready endpoints - all pods may be down or label selector mismatch", svcName),
				Remediation: fmt.Sprintf("kubectl get endpoints %s -n %s && kubectl get pods -n %s -l app=%s", svcName, ns, ns, svcName),
			})
		} else {
			hop.Issues = append(hop.Issues, HopIssue{
				Severity:    "INFO",
				Description: fmt.Sprintf("%d ready endpoints", readyCount),
			})
		}
	}

	if hop.Status == "" {
		hop.Status = "PASS"
		hop.Description = fmt.Sprintf("Service '%s' exists with port %d", svcName, port)
	}
	return hop
}

func (ca *ConnectivityAnalyzer) computeVerdict(hops []TrafficHop, blockedAt *string) string {
	for _, hop := range hops {
		if hop.Status == "FAIL" {
			*blockedAt = hop.Name
			return "BLOCKED"
		}
	}
	hasWarn := false
	for _, hop := range hops {
		if hop.Status == "WARN" {
			hasWarn = true
		}
	}
	if hasWarn {
		return "LIKELY_ALLOWED_WITH_WARNINGS"
	}
	return "ALLOWED"
}

func (ca *ConnectivityAnalyzer) buildSummary(result *TraceResult) []string {
	var summary []string
	switch result.Verdict {
	case "ALLOWED":
		summary = append(summary, fmt.Sprintf("✓ Traffic from '%s' to '%s' should be ALLOWED", result.Source, result.Destination))
	case "BLOCKED":
		summary = append(summary, fmt.Sprintf("✗ Traffic BLOCKED at: %s", result.BlockedAt))
	case "LIKELY_ALLOWED_WITH_WARNINGS":
		summary = append(summary, fmt.Sprintf("⚠ Traffic likely allowed but warnings found - verify manually"))
	}

	// Add actionable items
	for _, hop := range result.Hops {
		for _, issue := range hop.Issues {
			if issue.Severity == "ERROR" && issue.Remediation != "" {
				summary = append(summary, fmt.Sprintf("→ Fix: %s", issue.Remediation))
			}
		}
	}
	return summary
}

// Helpers

func parseDestination(dest string) (namespace, service string, port uint32, isExternal bool) {
	// Formats: namespace/service:port or external-host:port
	if strings.Contains(dest, "/") {
		parts := strings.SplitN(dest, "/", 2)
		namespace = parts[0]
		hostPort := parts[1]
		if idx := strings.LastIndex(hostPort, ":"); idx >= 0 {
			service = hostPort[:idx]
			fmt.Sscanf(hostPort[idx+1:], "%d", &port)
		} else {
			service = hostPort
		}
		return namespace, service, port, false
	}
	// External host
	if idx := strings.LastIndex(dest, ":"); idx >= 0 {
		service = dest[:idx]
		fmt.Sscanf(dest[idx+1:], "%d", &port)
	} else {
		service = dest
	}
	return "", service, port, true
}

func validPortName(name string) bool {
	validPrefixes := []string{"http", "https", "grpc", "grpc-web", "tcp", "tls", "mongo", "redis", "mysql"}
	nameLower := strings.ToLower(name)
	for _, p := range validPrefixes {
		if nameLower == p || strings.HasPrefix(nameLower, p+"-") {
			return true
		}
	}
	return false
}

func labelsMatchNetPol(selector, podLabels map[string]string) bool {
	if len(selector) == 0 {
		return true // Empty selector matches all pods
	}
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}
