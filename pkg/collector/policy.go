package collector

import (
	"context"
	"fmt"

	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	networkv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"golang.org/x/sync/errgroup"

	"github.com/istio-doctor/pkg/client"
)

// PolicyCollection holds all Istio and Kubernetes policy resources.
type PolicyCollection struct {
	AuthorizationPolicies []securityv1beta1.AuthorizationPolicy   `json:"authorization_policies"`
	PeerAuthentications   []securityv1beta1.PeerAuthentication    `json:"peer_authentications"`
	RequestAuthentications []securityv1beta1.RequestAuthentication `json:"request_authentications"`
	VirtualServices       []networkingv1alpha3.VirtualService      `json:"virtual_services"`
	DestinationRules      []networkingv1alpha3.DestinationRule     `json:"destination_rules"`
	Gateways              []networkingv1alpha3.Gateway             `json:"gateways"`
	ServiceEntries        []networkingv1alpha3.ServiceEntry        `json:"service_entries"`
	Sidecars              []networkingv1alpha3.Sidecar             `json:"sidecars"`
	EnvoyFilters          []networkingv1alpha3.EnvoyFilter         `json:"envoy_filters"`
	NetworkPolicies       []networkv1.NetworkPolicy                `json:"network_policies"`
}

// PolicyCollector collects all mesh policy resources in parallel.
type PolicyCollector struct {
	client *client.IstioClient
}

func NewPolicyCollector(c *client.IstioClient) *PolicyCollector {
	return &PolicyCollector{client: c}
}

// Collect gathers all policies across the given namespace (empty = all).
func (p *PolicyCollector) Collect(ctx context.Context, namespace string) (*PolicyCollection, error) {
	collection := &PolicyCollection{}
	g, ctx := errgroup.WithContext(ctx)

	var (
		authzPolicies    []securityv1beta1.AuthorizationPolicy
		peerAuths        []securityv1beta1.PeerAuthentication
		requestAuths     []securityv1beta1.RequestAuthentication
		virtualServices  []networkingv1alpha3.VirtualService
		destinationRules []networkingv1alpha3.DestinationRule
		gateways         []networkingv1alpha3.Gateway
		serviceEntries   []networkingv1alpha3.ServiceEntry
		sidecars         []networkingv1alpha3.Sidecar
		envoyFilters     []networkingv1alpha3.EnvoyFilter
		networkPolicies  []networkv1.NetworkPolicy
	)

	g.Go(func() error {
		list, err := p.client.Istio.SecurityV1beta1().AuthorizationPolicies(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list authorization policies: %w", err)
		}
		authzPolicies = list.Items
		return nil
	})

	g.Go(func() error {
		list, err := p.client.Istio.SecurityV1beta1().PeerAuthentications(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list peer authentications: %w", err)
		}
		peerAuths = list.Items
		return nil
	})

	g.Go(func() error {
		list, err := p.client.Istio.SecurityV1beta1().RequestAuthentications(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list request authentications: %w", err)
		}
		requestAuths = list.Items
		return nil
	})

	g.Go(func() error {
		list, err := p.client.Istio.NetworkingV1alpha3().VirtualServices(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list virtual services: %w", err)
		}
		virtualServices = list.Items
		return nil
	})

	g.Go(func() error {
		list, err := p.client.Istio.NetworkingV1alpha3().DestinationRules(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list destination rules: %w", err)
		}
		destinationRules = list.Items
		return nil
	})

	g.Go(func() error {
		list, err := p.client.Istio.NetworkingV1alpha3().Gateways(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list gateways: %w", err)
		}
		gateways = list.Items
		return nil
	})

	g.Go(func() error {
		list, err := p.client.Istio.NetworkingV1alpha3().ServiceEntries(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list service entries: %w", err)
		}
		serviceEntries = list.Items
		return nil
	})

	g.Go(func() error {
		list, err := p.client.Istio.NetworkingV1alpha3().Sidecars(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list sidecars: %w", err)
		}
		sidecars = list.Items
		return nil
	})

	g.Go(func() error {
		list, err := p.client.Istio.NetworkingV1alpha3().EnvoyFilters(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list envoy filters: %w", err)
		}
		envoyFilters = list.Items
		return nil
	})

	g.Go(func() error {
		list, err := p.client.K8s.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list network policies: %w", err)
		}
		networkPolicies = list.Items
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	collection.AuthorizationPolicies = authzPolicies
	collection.PeerAuthentications = peerAuths
	collection.RequestAuthentications = requestAuths
	collection.VirtualServices = virtualServices
	collection.DestinationRules = destinationRules
	collection.Gateways = gateways
	collection.ServiceEntries = serviceEntries
	collection.Sidecars = sidecars
	collection.EnvoyFilters = envoyFilters
	collection.NetworkPolicies = networkPolicies

	return collection, nil
}

// Summary returns a count summary of all collected policies.
func (pc *PolicyCollection) Summary() map[string]int {
	return map[string]int{
		"authorization_policies":  len(pc.AuthorizationPolicies),
		"peer_authentications":    len(pc.PeerAuthentications),
		"request_authentications": len(pc.RequestAuthentications),
		"virtual_services":        len(pc.VirtualServices),
		"destination_rules":       len(pc.DestinationRules),
		"gateways":                len(pc.Gateways),
		"service_entries":         len(pc.ServiceEntries),
		"sidecars":                len(pc.Sidecars),
		"envoy_filters":           len(pc.EnvoyFilters),
		"network_policies":        len(pc.NetworkPolicies),
	}
}

// FilterAuthzByNamespace returns authorization policies in a namespace.
func (pc *PolicyCollection) FilterAuthzByNamespace(ns string) []securityv1beta1.AuthorizationPolicy {
	var result []securityv1beta1.AuthorizationPolicy
	for _, ap := range pc.AuthorizationPolicies {
		if ap.Namespace == ns {
			result = append(result, ap)
		}
	}
	return result
}

// FindGatewayForHost returns a Gateway that covers the given hostname.
func (pc *PolicyCollection) FindGatewayForHost(host string) *networkingv1alpha3.Gateway {
	for i, gw := range pc.Gateways {
		for _, server := range gw.Spec.Servers {
			for _, h := range server.Hosts {
				if matchesHost(h, host) {
					return &pc.Gateways[i]
				}
			}
		}
	}
	return nil
}

// FindVirtualServicesForGateway returns all VirtualServices attached to a gateway.
func (pc *PolicyCollection) FindVirtualServicesForGateway(gwNs, gwName string) []networkingv1alpha3.VirtualService {
	var result []networkingv1alpha3.VirtualService
	gwRef := fmt.Sprintf("%s/%s", gwNs, gwName)
	shortRef := gwName
	for _, vs := range pc.VirtualServices {
		for _, gw := range vs.Spec.Gateways {
			if gw == gwRef || gw == shortRef ||
				(vs.Namespace == gwNs && gw == gwName) {
				result = append(result, vs)
				break
			}
		}
	}
	return result
}

// FindServiceEntryForHost returns a ServiceEntry matching the given hostname.
func (pc *PolicyCollection) FindServiceEntryForHost(host string) *networkingv1alpha3.ServiceEntry {
	for i, se := range pc.ServiceEntries {
		for _, h := range se.Spec.Hosts {
			if matchesHost(h, host) {
				return &pc.ServiceEntries[i]
			}
		}
	}
	return nil
}

// FindDestinationRuleForHost returns a DestinationRule for the given hostname.
func (pc *PolicyCollection) FindDestinationRuleForHost(host, namespace string) *networkingv1alpha3.DestinationRule {
	// Prefer namespace-local, then root namespace
	for i, dr := range pc.DestinationRules {
		if matchesHost(dr.Spec.Host, host) && dr.Namespace == namespace {
			return &pc.DestinationRules[i]
		}
	}
	for i, dr := range pc.DestinationRules {
		if matchesHost(dr.Spec.Host, host) {
			return &pc.DestinationRules[i]
		}
	}
	return nil
}

// FindSidecarForWorkload returns the Sidecar CR that applies to a workload.
func (pc *PolicyCollection) FindSidecarForWorkload(namespace string, labels map[string]string) *networkingv1alpha3.Sidecar {
	// Namespace-specific sidecars take priority over root namespace
	for i, sc := range pc.Sidecars {
		if sc.Namespace != namespace {
			continue
		}
		ws := sc.Spec.GetWorkloadSelector()
		if ws == nil {
			// Applies to all workloads in namespace
			return &pc.Sidecars[i]
		}
		if labelsMatch(ws.Labels, labels) {
			return &pc.Sidecars[i]
		}
	}
	return nil
}

func labelsMatch(selector, podLabels map[string]string) bool {
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

func matchesHost(pattern, host string) bool {
	if pattern == "*" || pattern == host {
		return true
	}
	// Wildcard prefix match: *.example.com
	if len(pattern) > 2 && pattern[0] == '*' && pattern[1] == '.' {
		suffix := pattern[1:]
		return len(host) > len(suffix) && host[len(host)-len(suffix):] == suffix
	}
	// Namespace-scoped: host.namespace.svc.cluster.local
	return false
}
