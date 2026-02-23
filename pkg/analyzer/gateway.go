package analyzer

import (
	"context"
	"fmt"
	"strings"

	istiov1beta1api "istio.io/api/networking/v1alpha3"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/istio-doctor/pkg/client"
	"github.com/istio-doctor/pkg/collector"
	"github.com/istio-doctor/pkg/output"
)

// GatewayAnalyzer validates gateway configurations.
type GatewayAnalyzer struct {
	client   *client.IstioClient
	policies *collector.PolicyCollection
	authz    *AuthzAnalyzer
}

func NewGatewayAnalyzer(c *client.IstioClient, policies *collector.PolicyCollection) *GatewayAnalyzer {
	return &GatewayAnalyzer{
		client:   c,
		policies: policies,
		authz:    NewAuthzAnalyzer("cluster.local"),
	}
}

// GatewayReport holds the full gateway validation result.
type GatewayReport struct {
	IngressGateways []GatewayValidation
	EgressGateways  []GatewayValidation
}

// GatewayValidation is the validation result for a single gateway.
type GatewayValidation struct {
	GatewayName string
	Namespace   string
	Type        string // ingress or egress
	Findings    []output.Finding
	PodCount    int
	ReadyPods   int
}

// ValidateAll validates all gateways in the collection.
func (ga *GatewayAnalyzer) ValidateAll(ctx context.Context) (*GatewayReport, error) {
	report := &GatewayReport{}

	// Get gateway pod status
	gatewayPods, err := collector.CollectGatewayPods(ctx, ga.client)
	if err != nil {
		return nil, fmt.Errorf("collect gateway pods: %w", err)
	}

	podsByType := make(map[string][]collector.GatewayPodStatus)
	for _, pod := range gatewayPods {
		podsByType[pod.Type] = append(podsByType[pod.Type], pod)
	}

	for _, gw := range ga.policies.Gateways {
		gwType := detectGatewayType(gw)
		validation := ga.validateGateway(ctx, &gw, gwType, podsByType[gwType])

		if gwType == "egress" {
			report.EgressGateways = append(report.EgressGateways, validation)
		} else {
			report.IngressGateways = append(report.IngressGateways, validation)
		}
	}

	return report, nil
}

// ValidateGateway validates a specific named gateway.
func (ga *GatewayAnalyzer) ValidateGateway(ctx context.Context, namespace, name string) (*GatewayValidation, error) {
	gw, err := ga.client.Istio.NetworkingV1alpha3().Gateways(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get gateway: %w", err)
	}

	gatewayPods, _ := collector.CollectGatewayPods(ctx, ga.client)
	gwType := detectGatewayType(*gw)

	var relevantPods []collector.GatewayPodStatus
	for _, pod := range gatewayPods {
		if pod.Type == gwType {
			relevantPods = append(relevantPods, pod)
		}
	}

	v := ga.validateGateway(ctx, gw, gwType, relevantPods)
	return &v, nil
}

func (ga *GatewayAnalyzer) validateGateway(ctx context.Context, gw *networkingv1alpha3.Gateway, gwType string, pods []collector.GatewayPodStatus) GatewayValidation {
	v := GatewayValidation{
		GatewayName: gw.Name,
		Namespace:   gw.Namespace,
		Type:        gwType,
		PodCount:    len(pods),
	}

	for _, pod := range pods {
		if pod.Ready {
			v.ReadyPods++
		}
	}

	// 1. Check gateway pod health
	if len(pods) == 0 {
		v.Findings = append(v.Findings, output.Finding{
			ID:          "GW001",
			Severity:    output.SeverityCritical,
			Category:    "gateway",
			Resource:    fmt.Sprintf("gateway/%s", gw.Name),
			Namespace:   gw.Namespace,
			Message:     "No gateway pods found matching selector",
			Remediation: fmt.Sprintf("Check gateway deployment exists and selector matches: kubectl get pods -n %s -l istio=%sgateway", gw.Namespace, gwType),
		})
	} else if v.ReadyPods < v.PodCount {
		v.Findings = append(v.Findings, output.Finding{
			ID:          "GW002",
			Severity:    output.SeverityError,
			Category:    "gateway",
			Resource:    fmt.Sprintf("gateway/%s", gw.Name),
			Namespace:   gw.Namespace,
			Message:     fmt.Sprintf("Only %d/%d gateway pods are ready", v.ReadyPods, v.PodCount),
			Remediation: fmt.Sprintf("kubectl get pods -n %s -l istio=%sgateway -o wide", gw.Namespace, gwType),
		})
	} else {
		v.Findings = append(v.Findings, output.Finding{
			ID:       "GW000",
			Severity: output.SeverityPass,
			Category: "gateway",
			Resource: fmt.Sprintf("gateway/%s", gw.Name),
			Namespace: gw.Namespace,
			Message:  fmt.Sprintf("All %d gateway pods are ready", v.PodCount),
		})
	}

	// 2. Validate each server in the gateway
	for si, server := range gw.Spec.Servers {
		// Check TLS configuration
		if server.Tls != nil {
			ga.validateServerTLS(gw, si, &v)
		} else if isHTTPSPort(server.Port) {
			v.Findings = append(v.Findings, output.Finding{
				ID:          "GW010",
				Severity:    output.SeverityWarning,
				Category:    "gateway-tls",
				Resource:    fmt.Sprintf("gateway/%s server[%d]", gw.Name, si),
				Namespace:   gw.Namespace,
				Message:     fmt.Sprintf("Port %d looks like HTTPS but no TLS config defined", server.Port.Number),
				Remediation: "Add spec.servers[].tls configuration",
			})
		}

		// Check hosts are valid
		for _, host := range server.Hosts {
			if host == "" {
				v.Findings = append(v.Findings, output.Finding{
					ID:       "GW011",
					Severity: output.SeverityError,
					Category: "gateway",
					Resource: fmt.Sprintf("gateway/%s server[%d]", gw.Name, si),
					Namespace: gw.Namespace,
					Message:  "Empty host in gateway server - will not match any traffic",
				})
			}
		}

		// 3. Find attached VirtualServices and validate routing
		ga.validateVirtualServiceAttachment(ctx, gw, server.Hosts, &v)
	}

	// 4. Check for orphaned VirtualServices referencing this gateway
	ga.validateOrphanedVirtualServices(gw, &v)

	// 5. For egress gateways, check AuthZ policy allowing ingress to egress gateway
	if gwType == "egress" {
		ga.validateEgressAuthzPolicy(gw, &v)
	}

	// 6. Check for interfering EnvoyFilters
	ga.checkEnvoyFilters(gw, &v)

	return v
}

func (ga *GatewayAnalyzer) validateServerTLS(gw *networkingv1alpha3.Gateway, serverIdx int, v *GatewayValidation) {
	for _, s := range gw.Spec.Servers {
		if s.Tls == nil {
			continue
		}
		tls := s.Tls
		mode := tls.GetMode().String()

		// SIMPLE and MUTUAL modes require a credential name
		if (mode == "SIMPLE" || mode == "MUTUAL") && tls.GetCredentialName() == "" {
			v.Findings = append(v.Findings, output.Finding{
				ID:          "GW020",
				Severity:    output.SeverityError,
				Category:    "gateway-tls",
				Resource:    fmt.Sprintf("gateway/%s", gw.Name),
				Namespace:   gw.Namespace,
				Message:     fmt.Sprintf("TLS mode %s requires credentialName but none specified", mode),
				Detail:      "Without credentialName, Istio cannot serve TLS - connections will fail",
				Remediation: "Set spec.servers[].tls.credentialName to the name of the TLS secret in istio-system",
			})
		}

		// PASSTHROUGH should not have certif configs
		if mode == "PASSTHROUGH" && tls.GetCredentialName() != "" {
			v.Findings = append(v.Findings, output.Finding{
				ID:       "GW021",
				Severity: output.SeverityWarning,
				Category: "gateway-tls",
				Resource: fmt.Sprintf("gateway/%s", gw.Name),
				Namespace: gw.Namespace,
				Message:  "TLS PASSTHROUGH mode has credentialName set - this is ignored",
			})
		}
	}
}

func (ga *GatewayAnalyzer) validateVirtualServiceAttachment(ctx context.Context, gw *networkingv1alpha3.Gateway, gwHosts []string, v *GatewayValidation) {
	vss := ga.policies.FindVirtualServicesForGateway(gw.Namespace, gw.Name)

	if len(vss) == 0 {
		v.Findings = append(v.Findings, output.Finding{
			ID:          "GW030",
			Severity:    output.SeverityWarning,
			Category:    "gateway-routing",
			Resource:    fmt.Sprintf("gateway/%s", gw.Name),
			Namespace:   gw.Namespace,
			Message:     "No VirtualServices are attached to this gateway - no traffic will be routed",
			Remediation: fmt.Sprintf("Create a VirtualService with spec.gateways: [\"%s/%s\"]", gw.Namespace, gw.Name),
		})
		return
	}

	for _, vs := range vss {
		// Validate VS hosts match gateway server hosts
		for _, vsHost := range vs.Spec.Hosts {
			found := false
			for _, gwHost := range gwHosts {
				if gwHostMatchesVSHost(gwHost, vsHost) {
					found = true
					break
				}
			}
			if !found {
				v.Findings = append(v.Findings, output.Finding{
					ID:          "GW031",
					Severity:    output.SeverityError,
					Category:    "gateway-routing",
					Resource:    fmt.Sprintf("virtualservice/%s/%s", vs.Namespace, vs.Name),
					Namespace:   vs.Namespace,
					Message:     fmt.Sprintf("VirtualService host '%s' not covered by Gateway '%s' server hosts", vsHost, gw.Name),
					Detail:      fmt.Sprintf("Gateway hosts: %v, VirtualService host: %s", gwHosts, vsHost),
					Remediation: fmt.Sprintf("Add '%s' to Gateway spec.servers[].hosts or change VirtualService host", vsHost),
				})
			}
		}

		// Validate HTTP route destinations exist
		for ri, httpRoute := range vs.Spec.Http {
			for _, dest := range httpRoute.GetRoute() {
				if dest.Destination == nil {
					continue
				}
				destHost := dest.Destination.Host
				destPort := uint32(0)
				if dest.Destination.Port != nil {
					destPort = dest.Destination.Port.Number
				}

				// Check if destination service exists
				ns := vs.Namespace
				svc, err := ga.client.K8s.CoreV1().Services(ns).Get(ctx, destHost, metav1.GetOptions{})
				if err != nil {
					// May be a fully qualified hostname
					if !strings.Contains(destHost, ".") {
						v.Findings = append(v.Findings, output.Finding{
							ID:          "GW032",
							Severity:    output.SeverityError,
							Category:    "gateway-routing",
							Resource:    fmt.Sprintf("virtualservice/%s/%s http[%d]", vs.Namespace, vs.Name, ri),
							Namespace:   vs.Namespace,
							Message:     fmt.Sprintf("Route destination service '%s' not found in namespace '%s'", destHost, ns),
							Remediation: fmt.Sprintf("kubectl get svc %s -n %s", destHost, ns),
						})
					}
					continue
				}

				// Check port exists and is named correctly
				if destPort > 0 {
					portOK := false
					for _, sp := range svc.Spec.Ports {
						if sp.Port == int32(destPort) {
							portOK = true
							if !validPortName(sp.Name) {
								v.Findings = append(v.Findings, output.Finding{
									ID:       "GW033",
									Severity: output.SeverityWarning,
									Category: "gateway-routing",
									Resource: fmt.Sprintf("service/%s", svc.Name),
									Namespace: ns,
									Message:  fmt.Sprintf("Service port %d name '%s' may not enable proper Istio protocol detection", destPort, sp.Name),
									Remediation: "Use protocol-prefixed names: http, https, grpc, tcp, etc.",
								})
							}
						}
					}
					if !portOK {
						v.Findings = append(v.Findings, output.Finding{
							ID:          "GW034",
							Severity:    output.SeverityError,
							Category:    "gateway-routing",
							Resource:    fmt.Sprintf("virtualservice/%s", vs.Name),
							Namespace:   vs.Namespace,
							Message:     fmt.Sprintf("Service '%s' has no port %d (referenced by VirtualService)", destHost, destPort),
							Remediation: fmt.Sprintf("Check port number in VirtualService route or add port to service '%s'", destHost),
						})
					}
				}
			}
		}

		// Validate AuthZ: ingress gateway SA can reach destination
		ga.validateIngressAuthz(ctx, &vs, v)
	}
}

func (ga *GatewayAnalyzer) validateIngressAuthz(ctx context.Context, vs *networkingv1alpha3.VirtualService, v *GatewayValidation) {
	for _, httpRoute := range vs.Spec.Http {
		for _, dest := range httpRoute.GetRoute() {
			if dest.Destination == nil {
				continue
			}
			destHost := dest.Destination.Host
			destPort := uint32(80)
			if dest.Destination.Port != nil {
				destPort = dest.Destination.Port.Number
			}

			// Build a traffic request as if ingress gateway is the source
			req := &TrafficRequest{
				SourceNamespace:      "istio-system",
				SourceServiceAccount: "istio-ingressgateway-service-account",
				SourcePrincipal:      "spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account",
				DestNamespace:        vs.Namespace,
				DestService:          destHost,
				DestPort:             destPort,
				Method:               "GET",
				DestPath:             "/",
			}

			decision := ga.authz.Evaluate(req, ga.policies.AuthorizationPolicies)
			if !decision.Allowed {
				v.Findings = append(v.Findings, output.Finding{
					ID:          "GW040",
					Severity:    output.SeverityError,
					Category:    "gateway-authz",
					Resource:    fmt.Sprintf("virtualservice/%s/%s", vs.Namespace, vs.Name),
					Namespace:   vs.Namespace,
					Message:     fmt.Sprintf("Ingress gateway not authorized to reach '%s:%d': %s", destHost, destPort, decision.Reason),
					Detail:      fmt.Sprintf("Source principal: %s", req.SourcePrincipal),
					Remediation: fmt.Sprintf("Create AuthorizationPolicy in ns '%s' allowing principal '%s'", vs.Namespace, req.SourcePrincipal),
				})
			}
		}
	}
}

func (ga *GatewayAnalyzer) validateOrphanedVirtualServices(gw *networkingv1alpha3.Gateway, v *GatewayValidation) {
	// Check for VirtualServices that reference this gateway but the gateway doesn't serve their hosts
	for _, vs := range ga.policies.VirtualServices {
		for _, gwRef := range vs.Spec.Gateways {
			if gwRef == gw.Name || gwRef == fmt.Sprintf("%s/%s", gw.Namespace, gw.Name) {
				// VS is attached, now check if all VS hosts are in Gateway
				for _, vsHost := range vs.Spec.Hosts {
					covered := false
					for _, server := range gw.Spec.Servers {
						for _, gwHost := range server.Hosts {
							if gwHostMatchesVSHost(gwHost, vsHost) {
								covered = true
								break
							}
						}
					}
					if !covered {
						v.Findings = append(v.Findings, output.Finding{
							ID:       "GW050",
							Severity: output.SeverityWarning,
							Category: "gateway-routing",
							Resource: fmt.Sprintf("virtualservice/%s/%s", vs.Namespace, vs.Name),
							Namespace: vs.Namespace,
							Message:  fmt.Sprintf("VirtualService references gateway '%s' but host '%s' is not served by the gateway", gw.Name, vsHost),
							Remediation: fmt.Sprintf("Add host '%s' to gateway '%s' server configuration", vsHost, gw.Name),
						})
					}
				}
			}
		}
	}
}

func (ga *GatewayAnalyzer) validateEgressAuthzPolicy(gw *networkingv1alpha3.Gateway, v *GatewayValidation) {
	// Check if there's an AuthZ policy allowing traffic into the egress gateway
	hasAuthzForEgress := false
	for _, ap := range ga.policies.AuthorizationPolicies {
		if ap.Namespace == gw.Namespace || ap.Namespace == "istio-system" {
			selector := ap.Spec.GetSelector()
			if selector != nil {
				labels := selector.MatchLabels
				if labels["istio"] == "egressgateway" {
					hasAuthzForEgress = true
					break
				}
			}
		}
	}

	if !hasAuthzForEgress {
		v.Findings = append(v.Findings, output.Finding{
			ID:          "GW060",
			Severity:    output.SeverityInfo,
			Category:    "gateway-authz",
			Resource:    fmt.Sprintf("gateway/%s", gw.Name),
			Namespace:   gw.Namespace,
			Message:     "No AuthorizationPolicy found targeting egress gateway - all traffic to egress gateway is allowed",
			Detail:      "This may be intentional if you rely on source-side policies, but it means any pod in the mesh can use the egress gateway",
			Remediation: "Consider adding AuthorizationPolicy with selector: istio: egressgateway to restrict which workloads can use egress gateway",
		})
	} else {
		v.Findings = append(v.Findings, output.Finding{
			ID:       "GW061",
			Severity: output.SeverityPass,
			Category: "gateway-authz",
			Resource: fmt.Sprintf("gateway/%s", gw.Name),
			Namespace: gw.Namespace,
			Message:  "AuthorizationPolicy found targeting egress gateway",
		})
	}
}

func (ga *GatewayAnalyzer) checkEnvoyFilters(gw *networkingv1alpha3.Gateway, v *GatewayValidation) {
	for _, ef := range ga.policies.EnvoyFilters {
		if ef.Namespace != gw.Namespace && ef.Namespace != "istio-system" {
			continue
		}
		ws := ef.Spec.GetWorkloadSelector()
		if ws == nil {
			// Applies to all workloads in namespace including gateway
			v.Findings = append(v.Findings, output.Finding{
				ID:       "GW070",
				Severity: output.SeverityInfo,
				Category: "gateway",
				Resource: fmt.Sprintf("envoyfilter/%s/%s", ef.Namespace, ef.Name),
				Namespace: ef.Namespace,
				Message:  fmt.Sprintf("EnvoyFilter '%s' has no workload selector - applies to gateway pods too. May interfere with routing.", ef.Name),
			})
		}
	}
}

func detectGatewayType(gw networkingv1alpha3.Gateway) string {
	sel := gw.Spec.GetSelector()
	if sel != nil {
		if v, ok := sel["istio"]; ok {
			if strings.Contains(v, "egress") {
				return "egress"
			}
		}
	}
	if strings.Contains(strings.ToLower(gw.Name), "egress") {
		return "egress"
	}
	return "ingress"
}

func gwHostMatchesVSHost(gwHost, vsHost string) bool {
	// Gateway hosts can be namespace/host format
	parts := strings.SplitN(gwHost, "/", 2)
	gwHostPart := gwHost
	if len(parts) == 2 {
		gwHostPart = parts[1]
	}

	if gwHostPart == "*" || gwHostPart == vsHost {
		return true
	}
	// Wildcard prefix
	if strings.HasPrefix(gwHostPart, "*.") {
		suffix := gwHostPart[1:]
		return strings.HasSuffix(vsHost, suffix)
	}
	return false
}

func isHTTPSPort(port *istiov1beta1api.Server_Port) bool {
	if port == nil {
		return false
	}
	n := port.GetNumber()
	name := strings.ToLower(port.GetName())
	return n == 443 || n == 8443 || strings.Contains(name, "https") || strings.Contains(name, "tls")
}
