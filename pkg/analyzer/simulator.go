package analyzer

import (
	"context"
	"fmt"
	"strings"

	istiov1beta1 "istio.io/api/security/v1beta1"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/istio-doctor/pkg/client"
	"github.com/istio-doctor/pkg/collector"
)

// SimulationResult holds the impact analysis of applying a new policy.
type SimulationResult struct {
	PolicyName      string
	PolicyNamespace string
	PolicyAction    string

	// Traffic flows that change
	NewlyAllowed  []TrafficFlow
	NewlyBlocked  []TrafficFlow
	Unchanged     []TrafficFlow

	// Warnings
	Warnings []string

	// Summary
	AffectedWorkloads int
	BlockedCount      int
	AllowedCount      int
}

// TrafficFlow represents a source-to-destination traffic relationship.
type TrafficFlow struct {
	Source      WorkloadRef
	Destination WorkloadRef
	Port        uint32
	Path        string
	PreviousDecision string
	NewDecision      string
	ChangeReason     string
}

// WorkloadRef identifies a workload.
type WorkloadRef struct {
	Namespace      string
	ServiceAccount string
	Principal      string
	PodCount       int
	ServiceName    string
}

// PolicySimulator simulates the impact of applying a new AuthorizationPolicy.
type PolicySimulator struct {
	client    *client.IstioClient
	policies  *collector.PolicyCollection
	authz     *AuthzAnalyzer
}

func NewPolicySimulator(c *client.IstioClient, policies *collector.PolicyCollection) *PolicySimulator {
	return &PolicySimulator{
		client:   c,
		policies: policies,
		authz:    NewAuthzAnalyzer("cluster.local"),
	}
}

// SimulateAuthzPolicy evaluates the impact of a new AuthorizationPolicy.
func (ps *PolicySimulator) SimulateAuthzPolicy(ctx context.Context, newPolicy *securityv1beta1.AuthorizationPolicy) (*SimulationResult, error) {
	result := &SimulationResult{
		PolicyName:      newPolicy.Name,
		PolicyNamespace: newPolicy.Namespace,
		PolicyAction:    newPolicy.Spec.GetAction().String(),
	}

	// Find all workloads that the policy selector applies to
	affectedPods, err := ps.findAffectedPods(ctx, newPolicy)
	if err != nil {
		return nil, fmt.Errorf("find affected pods: %w", err)
	}

	if len(affectedPods) == 0 {
		result.Warnings = append(result.Warnings,
			"⚠ Policy selector matches NO pods in the cluster - this policy will have no effect")
		return result, nil
	}

	result.AffectedWorkloads = len(affectedPods)

	// Enumerate potential traffic sources (all unique service accounts in mesh)
	sources, err := ps.enumerateSources(ctx)
	if err != nil {
		return nil, fmt.Errorf("enumerate sources: %w", err)
	}

	// For each affected pod, simulate traffic from each source
	for _, destPod := range affectedPods {
		for _, source := range sources {
			for _, port := range ps.getDestPorts(ctx, destPod) {
				trafficReq := &TrafficRequest{
					SourceNamespace:      source.Namespace,
					SourceServiceAccount: source.ServiceAccount,
					SourcePrincipal:      source.Principal,
					DestNamespace:        destPod.Namespace,
					DestService:          destPod.Name,
					DestPort:             port,
					Method:               "GET",
					DestPath:             "/",
				}

				// Evaluate WITHOUT the new policy
				decisionBefore := ps.authz.Evaluate(trafficReq, ps.policies.AuthorizationPolicies)

				// Evaluate WITH the new policy
				allPoliciesWithNew := append(ps.policies.AuthorizationPolicies, *newPolicy)
				decisionAfter := ps.authz.Evaluate(trafficReq, allPoliciesWithNew)

				// Check if anything changed
				if decisionBefore.Allowed != decisionAfter.Allowed {
					flow := TrafficFlow{
						Source: WorkloadRef{
							Namespace:      source.Namespace,
							ServiceAccount: source.ServiceAccount,
							Principal:      source.Principal,
						},
						Destination: WorkloadRef{
							Namespace:   destPod.Namespace,
							ServiceName: destPod.Name,
						},
						Port:             port,
						Path:             "/",
						PreviousDecision: decisionStr(decisionBefore),
						NewDecision:      decisionStr(decisionAfter),
						ChangeReason:     decisionAfter.Reason,
					}

					if decisionAfter.Allowed {
						result.NewlyAllowed = append(result.NewlyAllowed, flow)
						result.AllowedCount++
					} else {
						result.NewlyBlocked = append(result.NewlyBlocked, flow)
						result.BlockedCount++
					}
				} else {
					result.Unchanged = append(result.Unchanged, TrafficFlow{
						Source: WorkloadRef{
							Namespace:      source.Namespace,
							ServiceAccount: source.ServiceAccount,
						},
						Destination: WorkloadRef{
							Namespace:   destPod.Namespace,
							ServiceName: destPod.Name,
						},
						Port:             port,
						PreviousDecision: decisionStr(decisionBefore),
						NewDecision:      decisionStr(decisionAfter),
					})
				}
			}
		}
	}

	// Add warnings for dangerous patterns
	ps.addSimulationWarnings(newPolicy, result)

	return result, nil
}

// findAffectedPods returns pods that the policy's workload selector targets.
func (ps *PolicySimulator) findAffectedPods(ctx context.Context, policy *securityv1beta1.AuthorizationPolicy) ([]corev1.Pod, error) {
	selector := policy.Spec.GetSelector()

	listOpts := metav1.ListOptions{}
	if selector != nil && len(selector.MatchLabels) > 0 {
		listOpts.LabelSelector = labelsToSelector(selector.MatchLabels)
	}

	podList, err := ps.client.K8s.CoreV1().Pods(policy.Namespace).List(ctx, listOpts)
	if err != nil {
		return nil, err
	}

	var running []corev1.Pod
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning && client.IsSidecarInjected(&pod) {
			running = append(running, pod)
		}
	}
	return running, nil
}

type sourceIdentity struct {
	Namespace      string
	ServiceAccount string
	Principal      string
}

// enumerateSources returns unique service account identities in the mesh.
func (ps *PolicySimulator) enumerateSources(ctx context.Context) ([]sourceIdentity, error) {
	pods, err := ps.client.K8s.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "security.istio.io/tlsMode=istio",
	})
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var sources []sourceIdentity

	for _, pod := range pods.Items {
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		key := fmt.Sprintf("%s/%s", pod.Namespace, sa)
		if seen[key] {
			continue
		}
		seen[key] = true
		sources = append(sources, sourceIdentity{
			Namespace:      pod.Namespace,
			ServiceAccount: sa,
			Principal:      client.GetWorkloadIdentity(&pod),
		})
	}

	// Also add ingress gateway as a source
	sources = append(sources, sourceIdentity{
		Namespace:      "istio-system",
		ServiceAccount: "istio-ingressgateway-service-account",
		Principal:      "spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account",
	})

	return sources, nil
}

// getDestPorts returns the ports exposed by a pod.
func (ps *PolicySimulator) getDestPorts(ctx context.Context, pod corev1.Pod) []uint32 {
	var ports []uint32
	seen := make(map[uint32]bool)

	for _, c := range pod.Spec.Containers {
		for _, p := range c.Ports {
			port := uint32(p.ContainerPort)
			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}

	if len(ports) == 0 {
		ports = []uint32{80, 8080} // Common defaults
	}
	return ports
}

func (ps *PolicySimulator) addSimulationWarnings(policy *securityv1beta1.AuthorizationPolicy, result *SimulationResult) {
	action := policy.Spec.GetAction()

	// ALLOW with empty rules
	if action == istiov1beta1.AuthorizationPolicy_ALLOW && len(policy.Spec.GetRules()) == 0 {
		result.Warnings = append(result.Warnings,
			"🚨 CRITICAL: This ALLOW policy has empty rules[] - it will DENY all traffic to affected workloads!")
	}

	// Large blast radius
	if result.BlockedCount > 10 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("🔥 HIGH IMPACT: This policy will block %d traffic flows. Review carefully before applying.", result.BlockedCount))
	}

	// DENY policy without from/to constraints = blocks everything
	if action == istiov1beta1.AuthorizationPolicy_DENY {
		for ri, rule := range policy.Spec.GetRules() {
			if len(rule.GetFrom()) == 0 && len(rule.GetTo()) == 0 {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("⚠ DENY rule[%d] has no from/to constraints - blocks ALL traffic to affected workloads", ri))
			}
		}
	}

	// Principal format warnings
	for _, rule := range policy.Spec.GetRules() {
		for _, from := range rule.GetFrom() {
			for _, principal := range from.GetSource().GetPrincipals() {
				if !strings.HasPrefix(principal, "spiffe://") && principal != "*" {
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("⚠ Principal '%s' doesn't start with 'spiffe://' - may never match any workload", principal))
				}
			}
		}
	}
}

func decisionStr(d *AuthzDecision) string {
	if d.Allowed {
		return "ALLOW"
	}
	return "DENY"
}

// SimulationSummary formats a human-readable summary of the simulation.
func (r *SimulationResult) SimulationSummary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Policy: %s/%s (Action: %s)\n", r.PolicyNamespace, r.PolicyName, r.PolicyAction))
	sb.WriteString(fmt.Sprintf("Affected workloads: %d\n\n", r.AffectedWorkloads))

	if len(r.Warnings) > 0 {
		sb.WriteString("WARNINGS:\n")
		for _, w := range r.Warnings {
			sb.WriteString("  " + w + "\n")
		}
		sb.WriteString("\n")
	}

	if r.BlockedCount == 0 && r.AllowedCount == 0 {
		sb.WriteString("✓ No traffic flow changes detected\n")
		return sb.String()
	}

	if r.AllowedCount > 0 {
		sb.WriteString(fmt.Sprintf("Newly ALLOWED (%d flows):\n", r.AllowedCount))
		for _, flow := range r.NewlyAllowed {
			sb.WriteString(fmt.Sprintf("  + %s/%s → %s/%s:%d\n",
				flow.Source.Namespace, flow.Source.ServiceAccount,
				flow.Destination.Namespace, flow.Destination.ServiceName, flow.Port))
		}
		sb.WriteString("\n")
	}

	if r.BlockedCount > 0 {
		sb.WriteString(fmt.Sprintf("Newly BLOCKED (%d flows):\n", r.BlockedCount))
		for _, flow := range r.NewlyBlocked {
			sb.WriteString(fmt.Sprintf("  - %s/%s → %s/%s:%d  (reason: %s)\n",
				flow.Source.Namespace, flow.Source.ServiceAccount,
				flow.Destination.Namespace, flow.Destination.ServiceName, flow.Port,
				flow.ChangeReason))
		}
	}

	return sb.String()
}
