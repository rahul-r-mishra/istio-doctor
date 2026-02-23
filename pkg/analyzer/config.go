package analyzer

import (
	"context"
	"fmt"
	"strings"

	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/istio-doctor/pkg/client"
	"github.com/istio-doctor/pkg/collector"
	"github.com/istio-doctor/pkg/output"
)

// ConfigAnalyzer finds configuration problems across all Istio resources.
type ConfigAnalyzer struct {
	client   *client.IstioClient
	policies *collector.PolicyCollection
}

func NewConfigAnalyzer(c *client.IstioClient, policies *collector.PolicyCollection) *ConfigAnalyzer {
	return &ConfigAnalyzer{client: c, policies: policies}
}

// Analyze performs full configuration analysis and returns findings.
func (ca *ConfigAnalyzer) Analyze(ctx context.Context, namespace string) []output.Finding {
	var findings []output.Finding

	findings = append(findings, ca.checkVirtualServices(ctx, namespace)...)
	findings = append(findings, ca.checkDestinationRules(ctx, namespace)...)
	findings = append(findings, ca.checkServiceEntries(ctx, namespace)...)
	findings = append(findings, ca.checkPeerAuthentication(ctx, namespace)...)
	findings = append(findings, ca.checkSidecars(ctx, namespace)...)
	findings = append(findings, ca.checkEnvoyFilters(ctx, namespace)...)
	findings = append(findings, ca.checkVersionSkew(ctx)...)

	return findings
}

// checkVirtualServices finds orphaned, misconfigured VirtualServices.
func (ca *ConfigAnalyzer) checkVirtualServices(ctx context.Context, namespace string) []output.Finding {
	var findings []output.Finding

	for _, vs := range ca.policies.VirtualServices {
		if namespace != "" && vs.Namespace != namespace {
			continue
		}

		// 1. Check VS hosts resolve to existing services or service entries
		for _, host := range vs.Spec.Hosts {
			if host == "*" {
				continue
			}
			if !ca.hostExists(ctx, host, vs.Namespace) {
				findings = append(findings, output.Finding{
					ID:          "VS001",
					Severity:    output.SeverityError,
					Category:    "virtual-service",
					Resource:    fmt.Sprintf("virtualservice/%s", vs.Name),
					Namespace:   vs.Namespace,
					Message:     fmt.Sprintf("VirtualService host '%s' does not resolve to a Service or ServiceEntry", host),
					Detail:      "Istio will ignore this VirtualService if the host cannot be resolved",
					Remediation: fmt.Sprintf("Create Service or ServiceEntry for host '%s', or fix the host name", host),
				})
			}
		}

		// 2. Check VS gateway references resolve
		for _, gwRef := range vs.Spec.Gateways {
			if gwRef == "mesh" {
				continue
			}
			if !ca.gatewayExists(gwRef, vs.Namespace) {
				findings = append(findings, output.Finding{
					ID:          "VS002",
					Severity:    output.SeverityError,
					Category:    "virtual-service",
					Resource:    fmt.Sprintf("virtualservice/%s", vs.Name),
					Namespace:   vs.Namespace,
					Message:     fmt.Sprintf("VirtualService references non-existent Gateway '%s'", gwRef),
					Remediation: fmt.Sprintf("Create Gateway '%s' or remove it from spec.gateways", gwRef),
				})
			}
		}

		// 3. Check destination subsets reference existing DestinationRule subsets
		for hi, httpRoute := range vs.Spec.Http {
			for ri, route := range httpRoute.GetRoute() {
				if route.Destination == nil || route.Destination.Subset == "" {
					continue
				}
				host := route.Destination.Host
				subset := route.Destination.Subset

				if !ca.subsetExists(host, subset, vs.Namespace) {
					findings = append(findings, output.Finding{
						ID:          "VS003",
						Severity:    output.SeverityError,
						Category:    "virtual-service",
						Resource:    fmt.Sprintf("virtualservice/%s http[%d].route[%d]", vs.Name, hi, ri),
						Namespace:   vs.Namespace,
						Message:     fmt.Sprintf("Subset '%s' not defined in DestinationRule for host '%s'", subset, host),
						Detail:      "Traffic to this route will fail - Envoy cannot find the subset",
						Remediation: fmt.Sprintf("Add subset '%s' to DestinationRule for host '%s'", subset, host),
					})
				}
			}
		}

		// 4. Check for header-based routing without explicit order (possible shadowing)
		if hasOverlappingHTTPRoutes(vs) {
			findings = append(findings, output.Finding{
				ID:       "VS004",
				Severity: output.SeverityWarning,
				Category: "virtual-service",
				Resource: fmt.Sprintf("virtualservice/%s", vs.Name),
				Namespace: vs.Namespace,
				Message:  "VirtualService has HTTP routes that may shadow each other - Istio evaluates routes in order",
				Remediation: "Review route order and ensure more specific routes appear before catch-all routes",
			})
		}

		// 5. TCP routes without port specification can be ambiguous
		for ti, tcpRoute := range vs.Spec.Tcp {
			if len(tcpRoute.Match) == 0 {
				findings = append(findings, output.Finding{
					ID:       "VS005",
					Severity: output.SeverityWarning,
					Category: "virtual-service",
					Resource: fmt.Sprintf("virtualservice/%s tcp[%d]", vs.Name, ti),
					Namespace: vs.Namespace,
					Message:  "TCP route has no match conditions - matches all TCP traffic on all ports",
					Remediation: "Add port match conditions to be specific about which TCP traffic this route applies to",
				})
			}
		}
	}

	return findings
}

// checkDestinationRules finds DestinationRule misconfigurations.
func (ca *ConfigAnalyzer) checkDestinationRules(ctx context.Context, namespace string) []output.Finding {
	var findings []output.Finding

	for _, dr := range ca.policies.DestinationRules {
		if namespace != "" && dr.Namespace != namespace {
			continue
		}

		host := dr.Spec.Host

		// 1. Host should resolve
		if host != "*" && !ca.hostExists(ctx, host, dr.Namespace) {
			findings = append(findings, output.Finding{
				ID:          "DR001",
				Severity:    output.SeverityWarning,
				Category:    "destination-rule",
				Resource:    fmt.Sprintf("destinationrule/%s", dr.Name),
				Namespace:   dr.Namespace,
				Message:     fmt.Sprintf("DestinationRule host '%s' does not resolve to a Service or ServiceEntry", host),
				Remediation: "Verify host name is correct or create the corresponding Service/ServiceEntry",
			})
		}

		// 2. Check mTLS mode consistency with PeerAuthentication
		tp := dr.Spec.GetTrafficPolicy()
		if tp != nil && tp.GetTls() != nil {
			tlsMode := tp.GetTls().GetMode().String()
			// DISABLE mode on internal service is dangerous when STRICT PeerAuth exists
			if tlsMode == "DISABLE" {
				pa := ca.findPeerAuthForHost(host, dr.Namespace)
				if pa != nil && pa.Spec.GetMtls() != nil && pa.Spec.GetMtls().GetMode().String() == "STRICT" {
					findings = append(findings, output.Finding{
						ID:          "DR002",
						Severity:    output.SeverityCritical,
						Category:    "destination-rule",
						Resource:    fmt.Sprintf("destinationrule/%s", dr.Name),
						Namespace:   dr.Namespace,
						Message:     fmt.Sprintf("DestinationRule sets TLS DISABLE for host '%s' but PeerAuthentication '%s' requires STRICT mTLS - traffic will FAIL", host, pa.Name),
						Detail:      "When PeerAuthentication is STRICT, all sidecars reject plaintext. DestinationRule DISABLE tells the client to send plaintext.",
						Remediation: fmt.Sprintf("Change DestinationRule TLS mode to ISTIO_MUTUAL or remove conflicting PeerAuthentication '%s'", pa.Name),
					})
				}
			}
		}

		// 3. Check subset label selectors are non-empty
		for si, subset := range dr.Spec.Subsets {
			if len(subset.Labels) == 0 {
				findings = append(findings, output.Finding{
					ID:       "DR003",
					Severity: output.SeverityError,
					Category: "destination-rule",
					Resource: fmt.Sprintf("destinationrule/%s subset[%d]=%s", dr.Name, si, subset.Name),
					Namespace: dr.Namespace,
					Message:  fmt.Sprintf("Subset '%s' has no labels - will match ALL endpoints (unintentional?)", subset.Name),
					Remediation: fmt.Sprintf("Add label selector to subset '%s' to target specific pod versions/variants", subset.Name),
				})
			}
		}

		// 4. Connection pool settings sanity
		if tp != nil && tp.GetConnectionPool() != nil {
			cp := tp.GetConnectionPool()
			if cp.GetTcp() != nil && cp.GetTcp().GetMaxConnections() == 1 {
				findings = append(findings, output.Finding{
					ID:       "DR004",
					Severity: output.SeverityWarning,
					Category: "destination-rule",
					Resource: fmt.Sprintf("destinationrule/%s", dr.Name),
					Namespace: dr.Namespace,
					Message:  "maxConnections=1 is very restrictive - single connection per upstream. Likely causes performance issues at scale.",
					Remediation: "Increase connectionPool.tcp.maxConnections to match your expected concurrency",
				})
			}
		}
	}

	return findings
}

// checkServiceEntries finds ServiceEntry misconfigurations.
func (ca *ConfigAnalyzer) checkServiceEntries(ctx context.Context, namespace string) []output.Finding {
	var findings []output.Finding

	for _, se := range ca.policies.ServiceEntries {
		if namespace != "" && se.Namespace != namespace {
			continue
		}

		// 1. DNS resolution with static endpoints is contradictory
		resolution := se.Spec.GetResolution().String()
		if resolution == "STATIC" && len(se.Spec.Endpoints) == 0 {
			findings = append(findings, output.Finding{
				ID:          "SE001",
				Severity:    output.SeverityError,
				Category:    "service-entry",
				Resource:    fmt.Sprintf("serviceentry/%s", se.Name),
				Namespace:   se.Namespace,
				Message:     "ServiceEntry with STATIC resolution has no endpoints defined - traffic will fail",
				Remediation: "Add spec.endpoints[] or change resolution to DNS",
			})
		}

		// 2. External services with NONE resolution and ports
		if resolution == "NONE" && len(se.Spec.Ports) > 0 {
			for _, port := range se.Spec.Ports {
				if !validPortName(port.Name) {
					findings = append(findings, output.Finding{
						ID:       "SE002",
						Severity: output.SeverityWarning,
						Category: "service-entry",
						Resource: fmt.Sprintf("serviceentry/%s port=%s", se.Name, port.Name),
						Namespace: se.Namespace,
						Message:  fmt.Sprintf("ServiceEntry port '%s' may not be recognized for protocol detection", port.Name),
						Remediation: "Use protocol-prefixed port names: http, https, grpc, tcp",
					})
				}
			}
		}

		// 3. REGISTRY_ONLY mode: check if host conflicts with internal service
		for _, host := range se.Spec.Hosts {
			if !strings.Contains(host, ".") {
				findings = append(findings, output.Finding{
					ID:       "SE003",
					Severity: output.SeverityWarning,
					Category: "service-entry",
					Resource: fmt.Sprintf("serviceentry/%s", se.Name),
					Namespace: se.Namespace,
					Message:  fmt.Sprintf("ServiceEntry host '%s' has no dots - may conflict with internal Kubernetes services", host),
					Remediation: "Use fully qualified hostnames for external services (e.g., api.example.com)",
				})
			}
		}
	}

	return findings
}

// checkPeerAuthentication finds mTLS configuration issues.
func (ca *ConfigAnalyzer) checkPeerAuthentication(ctx context.Context, namespace string) []output.Finding {
	var findings []output.Finding

	// Check for namespace-wide STRICT policies
	var strictPolicies []networkingv1alpha3.Sidecar
	_ = strictPolicies

	for _, pa := range ca.policies.PeerAuthentications {
		if namespace != "" && pa.Namespace != namespace {
			continue
		}

		if pa.Spec.GetMtls() == nil {
			continue
		}
		mode := pa.Spec.GetMtls().GetMode().String()

		// Check for PERMISSIVE on namespace that may have had STRICT before
		if mode == "PERMISSIVE" && pa.Spec.GetSelector() == nil {
			findings = append(findings, output.Finding{
				ID:       "PA001",
				Severity: output.SeverityInfo,
				Category: "peer-auth",
				Resource: fmt.Sprintf("peerauthentication/%s", pa.Name),
				Namespace: pa.Namespace,
				Message:  fmt.Sprintf("Namespace-wide PeerAuthentication is PERMISSIVE - allows both plaintext and mTLS. Consider STRICT for security."),
				Remediation: "Change to STRICT mode if all clients are Istio-injected: kubectl patch peerauthentication " + pa.Name + " -n " + pa.Namespace + " --type=merge -p '{\"spec\":{\"mtls\":{\"mode\":\"STRICT\"}}}'",
			})
		}

		// Check for STRICT on namespace with known non-mesh workloads
		if mode == "STRICT" {
			// Check if there are pods without sidecars in this namespace
			nonMeshPods, err := ca.client.K8s.CoreV1().Pods(pa.Namespace).List(ctx, metav1.ListOptions{})
			if err == nil {
				nonMeshCount := 0
				for _, pod := range nonMeshPods.Items {
					if !client.IsSidecarInjected(&pod) && pod.Status.Phase == "Running" {
						nonMeshCount++
					}
				}
				if nonMeshCount > 0 {
					findings = append(findings, output.Finding{
						ID:          "PA002",
						Severity:    output.SeverityWarning,
						Category:    "peer-auth",
						Resource:    fmt.Sprintf("peerauthentication/%s", pa.Name),
						Namespace:   pa.Namespace,
						Message:     fmt.Sprintf("STRICT mTLS policy in namespace '%s' but %d pod(s) have no sidecar - they will not be able to receive traffic", pa.Namespace, nonMeshCount),
						Remediation: fmt.Sprintf("Inject sidecar into remaining pods or use PERMISSIVE mode: kubectl label namespace %s istio-injection=enabled", pa.Namespace),
					})
				}
			}
		}
	}

	return findings
}

// checkSidecars validates Sidecar CRs.
func (ca *ConfigAnalyzer) checkSidecars(ctx context.Context, namespace string) []output.Finding {
	var findings []output.Finding

	for _, sc := range ca.policies.Sidecars {
		if namespace != "" && sc.Namespace != namespace {
			continue
		}

		// Check egress hosts use valid format
		for _, egress := range sc.Spec.Egress {
			for _, host := range egress.Hosts {
				parts := strings.SplitN(host, "/", 2)
				if len(parts) != 2 {
					findings = append(findings, output.Finding{
						ID:          "SC001",
						Severity:    output.SeverityError,
						Category:    "sidecar",
						Resource:    fmt.Sprintf("sidecar/%s", sc.Name),
						Namespace:   sc.Namespace,
						Message:     fmt.Sprintf("Egress host '%s' is invalid - must be in format namespace/host (e.g., './my-service' or 'istio-system/*')", host),
						Remediation: fmt.Sprintf("Fix egress host format in Sidecar '%s'", sc.Name),
					})
				}
			}
		}

		// Check workload selector matches at least one pod
		ws := sc.Spec.GetWorkloadSelector()
		if ws != nil && len(ws.Labels) > 0 {
			pods, err := ca.client.K8s.CoreV1().Pods(sc.Namespace).List(ctx, metav1.ListOptions{
				LabelSelector: labelsToSelector(ws.Labels),
			})
			if err == nil && len(pods.Items) == 0 {
				findings = append(findings, output.Finding{
					ID:       "SC002",
					Severity: output.SeverityWarning,
					Category: "sidecar",
					Resource: fmt.Sprintf("sidecar/%s", sc.Name),
					Namespace: sc.Namespace,
					Message:  fmt.Sprintf("Sidecar workload selector matches no pods in namespace '%s'", sc.Namespace),
					Remediation: "Check if the workload selector labels are correct or if pods exist with those labels",
				})
			}
		}
	}

	return findings
}

// checkEnvoyFilters validates EnvoyFilter CRs.
func (ca *ConfigAnalyzer) checkEnvoyFilters(ctx context.Context, namespace string) []output.Finding {
	var findings []output.Finding

	for _, ef := range ca.policies.EnvoyFilters {
		if namespace != "" && ef.Namespace != namespace {
			continue
		}

		// Warn about EnvoyFilters in non-istio-system namespaces with no selector
		ws := ef.Spec.GetWorkloadSelector()
		if ws == nil && ef.Namespace != "istio-system" {
			findings = append(findings, output.Finding{
				ID:       "EF001",
				Severity: output.SeverityWarning,
				Category: "envoy-filter",
				Resource: fmt.Sprintf("envoyfilter/%s", ef.Name),
				Namespace: ef.Namespace,
				Message:  "EnvoyFilter has no workload selector - applies to ALL workloads in namespace including gateways. This is often unintentional.",
				Remediation: "Add spec.workloadSelector.labels to target specific workloads",
			})
		}

		// Check for EnvoyFilters with very low priority that could conflict
		if ef.Spec.Priority < -100 || ef.Spec.Priority > 100 {
			findings = append(findings, output.Finding{
				ID:       "EF002",
				Severity: output.SeverityInfo,
				Category: "envoy-filter",
				Resource: fmt.Sprintf("envoyfilter/%s", ef.Name),
				Namespace: ef.Namespace,
				Message:  fmt.Sprintf("EnvoyFilter has extreme priority %d - may unexpectedly override other filters", ef.Spec.Priority),
			})
		}
	}

	return findings
}

// checkVersionSkew detects version mismatch between istiod and data plane.
func (ca *ConfigAnalyzer) checkVersionSkew(ctx context.Context) []output.Finding {
	var findings []output.Finding

	// Collect proxy versions from pod annotations/labels
	versionCounts := make(map[string]int)
	pods, err := ca.client.K8s.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "security.istio.io/tlsMode=istio",
	})
	if err != nil {
		return findings
	}

	for _, pod := range pods.Items {
		for _, c := range pod.Spec.Containers {
			if c.Name == "istio-proxy" {
				parts := strings.Split(c.Image, ":")
				version := "unknown"
				if len(parts) > 1 {
					version = parts[len(parts)-1]
				}
				versionCounts[version]++
			}
		}
	}

	if len(versionCounts) > 2 {
		versions := make([]string, 0, len(versionCounts))
		for v := range versionCounts {
			versions = append(versions, v)
		}
		findings = append(findings, output.Finding{
			ID:          "VER001",
			Severity:    output.SeverityWarning,
			Category:    "version-skew",
			Resource:    "cluster",
			Message:     fmt.Sprintf("More than 2 distinct proxy versions detected (%d total): %s", len(versionCounts), strings.Join(versions, ", ")),
			Detail:      "Large version skew can cause unexpected behavior as different Envoy versions have different filter semantics",
			Remediation: "Perform rolling restart of workloads to update proxies: kubectl rollout restart deployment -A",
		})
	}

	return findings
}

// Helper methods

func (ca *ConfigAnalyzer) hostExists(ctx context.Context, host, namespace string) bool {
	// Check Kubernetes services
	shortHost := host
	if idx := strings.Index(host, "."); idx > 0 {
		shortHost = host[:idx]
	}
	_, err := ca.client.K8s.CoreV1().Services(namespace).Get(ctx, shortHost, metav1.GetOptions{})
	if err == nil {
		return true
	}
	// Check ServiceEntries
	if ca.policies.FindServiceEntryForHost(host) != nil {
		return true
	}
	// Allow * wildcards
	return host == "*"
}

func (ca *ConfigAnalyzer) gatewayExists(gwRef, namespace string) bool {
	for _, gw := range ca.policies.Gateways {
		if gw.Name == gwRef {
			return true
		}
		if fmt.Sprintf("%s/%s", gw.Namespace, gw.Name) == gwRef {
			return true
		}
		// Short ref in same namespace
		if gw.Namespace == namespace && gw.Name == gwRef {
			return true
		}
	}
	return false
}

func (ca *ConfigAnalyzer) subsetExists(host, subset, namespace string) bool {
	dr := ca.policies.FindDestinationRuleForHost(host, namespace)
	if dr == nil {
		return false
	}
	for _, s := range dr.Spec.Subsets {
		if s.Name == subset {
			return true
		}
	}
	return false
}

func (ca *ConfigAnalyzer) findPeerAuthForHost(host, namespace string) *securityv1beta1.PeerAuthentication {
	for i, pa := range ca.policies.PeerAuthentications {
		if pa.Namespace == namespace {
			return &ca.policies.PeerAuthentications[i]
		}
	}
	return nil
}

func hasOverlappingHTTPRoutes(vs networkingv1alpha3.VirtualService) bool {
	catchAllFound := false
	for _, route := range vs.Spec.Http {
		if len(route.Match) == 0 {
			if catchAllFound {
				return true // Second catch-all found
			}
			catchAllFound = true
		}
	}
	return false
}

func labelsToSelector(labels map[string]string) string {
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, ",")
}
