package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"golang.org/x/sync/semaphore"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"

	"github.com/istio-doctor/pkg/client"
)

// ProxyInfo holds the full proxy state for a single pod.
type ProxyInfo struct {
	PodName          string                   `json:"pod_name"`
	Namespace        string                   `json:"namespace"`
	PodIP            string                   `json:"pod_ip"`
	NodeName         string                   `json:"node_name"`
	ServiceAccount   string                   `json:"service_account"`
	WorkloadIdentity string                   `json:"workload_identity"`
	IstioVersion     string                   `json:"istio_version"`
	EnvoyVersion     string                   `json:"envoy_version"`
	SyncState        string                   `json:"sync_state"`
	Clusters         []EnvoyCluster           `json:"clusters,omitempty"`
	Listeners        []EnvoyListener          `json:"listeners,omitempty"`
	Routes           []EnvoyRoute             `json:"routes,omitempty"`
	Stats            map[string]string        `json:"stats,omitempty"`
	Config           *EnvoyConfigDump         `json:"config,omitempty"`
	Error            string                   `json:"error,omitempty"`
	CollectedAt      time.Time                `json:"collected_at"`
}

// EnvoyCluster holds cluster (upstream) info.
type EnvoyCluster struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	ConnectTimeout   string `json:"connect_timeout"`
	CircuitBreaking  string `json:"circuit_breaking,omitempty"`
	TLSMode          string `json:"tls_mode,omitempty"`
	HealthStatus     string `json:"health_status"`
	LocalityLB       bool   `json:"locality_lb"`
	EndpointCount    int    `json:"endpoint_count"`
}

// EnvoyListener holds listener info.
type EnvoyListener struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Port        uint32 `json:"port"`
	Direction   string `json:"direction"`
	FilterChain int    `json:"filter_chain_count"`
}

// EnvoyRoute holds route config info.
type EnvoyRoute struct {
	Name         string `json:"name"`
	VirtualHosts int    `json:"virtual_hosts"`
}

// EnvoyConfigDump is a light representation of an Envoy config dump.
type EnvoyConfigDump struct {
	Bootstrap    json.RawMessage `json:"bootstrap,omitempty"`
	StaticConfig json.RawMessage `json:"static_config,omitempty"`
}

// ProxyCollectionOptions controls what data to collect per proxy.
type ProxyCollectionOptions struct {
	CollectClusters  bool
	CollectListeners bool
	CollectRoutes    bool
	CollectStats     bool
	CollectConfig    bool
	StatFilter       string
	Concurrency      int
}

// DefaultProxyCollectionOptions returns sensible defaults.
func DefaultProxyCollectionOptions() ProxyCollectionOptions {
	return ProxyCollectionOptions{
		CollectClusters:  true,
		CollectListeners: true,
		CollectRoutes:    false,
		CollectStats:     false,
		Concurrency:      50,
	}
}

// ProxyCollector collects proxy state across all pods in parallel.
type ProxyCollector struct {
	client *client.IstioClient
}

func NewProxyCollector(c *client.IstioClient) *ProxyCollector {
	return &ProxyCollector{client: c}
}

// CollectAll collects proxy info for all sidecar-injected pods in a namespace.
func (p *ProxyCollector) CollectAll(ctx context.Context, namespace string, opts ProxyCollectionOptions) ([]*ProxyInfo, error) {
	listOpts := metav1.ListOptions{
		LabelSelector: "security.istio.io/tlsMode=istio",
	}
	podList, err := p.client.K8s.CoreV1().Pods(namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("list sidecar pods: %w", err)
	}

	return p.collectFromPods(ctx, podList.Items, opts)
}

// CollectForPod collects proxy info for a single specific pod.
func (p *ProxyCollector) CollectForPod(ctx context.Context, namespace, podName string, opts ProxyCollectionOptions) (*ProxyInfo, error) {
	pod, err := p.client.K8s.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod: %w", err)
	}
	results, err := p.collectFromPods(ctx, []corev1.Pod{*pod}, opts)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no proxy info collected for %s/%s", namespace, podName)
	}
	return results[0], nil
}

func (p *ProxyCollector) collectFromPods(ctx context.Context, pods []corev1.Pod, opts ProxyCollectionOptions) ([]*ProxyInfo, error) {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 50
	}

	sem := semaphore.NewWeighted(int64(concurrency))
	results := make([]*ProxyInfo, len(pods))
	var mu sync.Mutex
	_ = mu

	var wg sync.WaitGroup
	for i, pod := range pods {
		if !client.IsSidecarInjected(&pod) {
			continue
		}
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}

		wg.Add(1)
		go func(idx int, pod corev1.Pod) {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				return
			}
			defer sem.Release(1)

			info := p.collectPodProxy(ctx, &pod, opts)
			results[idx] = info
		}(i, pod)
	}

	wg.Wait()

	// Filter out nils (non-sidecar pods)
	var out []*ProxyInfo
	for _, r := range results {
		if r != nil {
			out = append(out, r)
		}
	}
	return out, nil
}

func (p *ProxyCollector) collectPodProxy(ctx context.Context, pod *corev1.Pod, opts ProxyCollectionOptions) *ProxyInfo {
	info := &ProxyInfo{
		PodName:          pod.Name,
		Namespace:        pod.Namespace,
		PodIP:            pod.Status.PodIP,
		NodeName:         pod.Spec.NodeName,
		ServiceAccount:   pod.Spec.ServiceAccountName,
		WorkloadIdentity: client.GetWorkloadIdentity(pod),
		CollectedAt:      time.Now(),
	}

	// Use exec into pod to hit the Envoy admin API on localhost:15000
	// This avoids needing port-forward per pod and is much faster at scale
	if opts.CollectClusters {
		clusterJSON, err := p.execEnvoyAdmin(ctx, pod, "/clusters?format=json")
		if err != nil {
			info.Error = fmt.Sprintf("envoy admin unreachable: %v", err)
			return info
		}
		clusters := parseEnvoyClusters(clusterJSON)
		info.Clusters = clusters
	}

	if opts.CollectListeners {
		listenerJSON, err := p.execEnvoyAdmin(ctx, pod, "/listeners?format=json")
		if err == nil {
			info.Listeners = parseEnvoyListeners(listenerJSON)
		}
	}

	if opts.CollectStats {
		statsPath := "/stats"
		if opts.StatFilter != "" {
			statsPath += "?filter=" + opts.StatFilter
		}
		statsData, err := p.execEnvoyAdmin(ctx, pod, statsPath)
		if err == nil {
			info.Stats = parseEnvoyStats(statsData)
		}
	}

	// Get istio-proxy version from container image tag
	for _, c := range pod.Spec.Containers {
		if c.Name == "istio-proxy" {
			parts := strings.Split(c.Image, ":")
			if len(parts) > 1 {
				info.IstioVersion = parts[len(parts)-1]
			}
		}
	}

	return info
}

// execEnvoyAdmin runs a curl command inside the istio-proxy container to hit the Envoy admin API.
func (p *ProxyCollector) execEnvoyAdmin(ctx context.Context, pod *corev1.Pod, path string) ([]byte, error) {
	cmd := []string{"pilot-agent", "request", "GET", path}

	req := p.client.K8s.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "istio-proxy",
			Command:   cmd,
			Stdout:    true,
			Stderr:    false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(p.client.RestConfig, http.MethodPost, req.URL())
	if err != nil {
		return nil, fmt.Errorf("create executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err = exec.StreamWithContext(ctxTimeout, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}

	return stdout.Bytes(), nil
}

// parseEnvoyClusters parses the Envoy /clusters?format=json response.
func parseEnvoyClusters(data []byte) []EnvoyCluster {
	var resp struct {
		ClusterStatuses []struct {
			Name          string `json:"name"`
			AddedViaAPI   bool   `json:"added_via_api"`
			HostStatuses  []struct {
				Address struct {
					SocketAddress struct {
						Address   string `json:"address"`
						PortValue uint32 `json:"port_value"`
					} `json:"socket_address"`
				} `json:"address"`
				Stats        []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"stats"`
				HealthStatus struct {
					EdsHealthStatus string `json:"eds_health_status"`
				} `json:"health_status"`
			} `json:"host_statuses"`
		} `json:"cluster_statuses"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil
	}

	var clusters []EnvoyCluster
	for _, cs := range resp.ClusterStatuses {
		healthStatus := "HEALTHY"
		if len(cs.HostStatuses) > 0 {
			healthStatus = cs.HostStatuses[0].HealthStatus.EdsHealthStatus
		}

		// Derive TLS mode from cluster name convention
		tlsMode := ""
		if strings.Contains(cs.Name, "tls") || strings.Contains(cs.Name, "https") {
			tlsMode = "TLS"
		}
		if strings.Contains(cs.Name, "mtls") || strings.Contains(cs.Name, "istio-mtls") {
			tlsMode = "MUTUAL_TLS"
		}

		clusters = append(clusters, EnvoyCluster{
			Name:          cs.Name,
			HealthStatus:  healthStatus,
			EndpointCount: len(cs.HostStatuses),
			TLSMode:       tlsMode,
		})
	}
	return clusters
}

// parseEnvoyListeners parses /listeners?format=json response.
func parseEnvoyListeners(data []byte) []EnvoyListener {
	var resp struct {
		ListenerStatuses []struct {
			Name string `json:"name"`
			LocalAddress struct {
				SocketAddress struct {
					Address   string `json:"address"`
					PortValue uint32 `json:"port_value"`
				} `json:"socket_address"`
			} `json:"local_address"`
		} `json:"listener_statuses"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil
	}

	var listeners []EnvoyListener
	for _, ls := range resp.ListenerStatuses {
		direction := "INBOUND"
		if ls.LocalAddress.SocketAddress.Address == "0.0.0.0" {
			direction = "OUTBOUND"
		}
		listeners = append(listeners, EnvoyListener{
			Name:      ls.Name,
			Address:   ls.LocalAddress.SocketAddress.Address,
			Port:      ls.LocalAddress.SocketAddress.PortValue,
			Direction: direction,
		})
	}
	return listeners
}

// parseEnvoyStats parses the /stats text response into a map.
func parseEnvoyStats(data []byte) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// GetConnectionErrors extracts upstream connection errors from proxy stats.
func GetConnectionErrors(stats map[string]string) map[string]string {
	errors := make(map[string]string)
	for k, v := range stats {
		if strings.Contains(k, "cx_connect_fail") ||
			strings.Contains(k, "upstream_cx_destroy_with_active_rq") ||
			strings.Contains(k, "upstream_rq_pending_failure_eject") ||
			strings.Contains(k, "upstream_rq_timeout") {
			if v != "0" {
				errors[k] = v
			}
		}
	}
	return errors
}

// GetCircuitBreakerTrips extracts circuit breaker trip stats.
func GetCircuitBreakerTrips(stats map[string]string) map[string]string {
	trips := make(map[string]string)
	for k, v := range stats {
		if strings.Contains(k, "overflow") || strings.Contains(k, "pending_overflow") {
			if v != "0" {
				trips[k] = v
			}
		}
	}
	return trips
}
