package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/istio-doctor/pkg/client"
)

// ControlPlaneStatus holds the health status of the Istio control plane.
type ControlPlaneStatus struct {
	IstiodPods        []IstiodPodStatus  `json:"istiod_pods"`
	SyncStatus        []ProxySyncStatus  `json:"sync_status"`
	PushStatus        *PushStatus        `json:"push_status,omitempty"`
	ConfigStatus      *ConfigStatus      `json:"config_status,omitempty"`
	VersionInfo       *VersionInfo       `json:"version_info,omitempty"`
	StalePodCount     int                `json:"stale_pod_count"`
	ErrorPodCount     int                `json:"error_pod_count"`
	SyncedPodCount    int                `json:"synced_pod_count"`
	TotalMeshPods     int                `json:"total_mesh_pods"`
	CollectedAt       time.Time          `json:"collected_at"`
}

// IstiodPodStatus represents an istiod pod's health.
type IstiodPodStatus struct {
	Name              string            `json:"name"`
	Ready             bool              `json:"ready"`
	Phase             corev1.PodPhase   `json:"phase"`
	RestartCount      int32             `json:"restart_count"`
	Age               time.Duration     `json:"age"`
	CPURequest        string            `json:"cpu_request,omitempty"`
	MemoryRequest     string            `json:"memory_request,omitempty"`
	CPULimit          string            `json:"cpu_limit,omitempty"`
	MemoryLimit       string            `json:"memory_limit,omitempty"`
}

// ProxySyncStatus represents the xDS sync state of a proxy.
type ProxySyncStatus struct {
	PodName           string    `json:"pod_name"`
	Namespace         string    `json:"namespace"`
	ClusterID         string    `json:"cluster_id"`
	IstioVersion      string    `json:"istio_version"`
	ClusterStatus     string    `json:"cluster_status"`
	ListenerStatus    string    `json:"listener_status"`
	RouteStatus       string    `json:"route_status"`
	EndpointStatus    string    `json:"endpoint_status"`
	SyncState         string    `json:"sync_state"` // SYNCED, STALE, NOT_SENT, ERROR
	LastSyncTime      time.Time `json:"last_sync_time,omitempty"`
	StaleSince        *float64  `json:"stale_since_seconds,omitempty"`
}

// PushStatus holds the latest xDS push information from istiod.
type PushStatus struct {
	LastPushTime      time.Time `json:"last_push_time"`
	LastPushDuration  string    `json:"last_push_duration"`
	TotalPushes       int64     `json:"total_pushes"`
	TotalErrors       int64     `json:"total_errors"`
	ProxyCount        int64     `json:"proxy_count"`
	PendingProxies    int64     `json:"pending_proxies"`
	Raw               string    `json:"-"`
}

// ConfigStatus holds the validation state of Istio configs.
type ConfigStatus struct {
	TotalResources    int      `json:"total_resources"`
	InvalidResources  int      `json:"invalid_resources"`
	OrphanedVS        []string `json:"orphaned_virtual_services,omitempty"`
	InvalidDR         []string `json:"invalid_destination_rules,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
}

// VersionInfo holds mesh version information.
type VersionInfo struct {
	IstiodVersion    string            `json:"istiod_version"`
	DataPlaneVersions map[string]int   `json:"data_plane_versions"`
	MixedVersions    bool              `json:"mixed_versions"`
}

// ControlPlaneCollector collects control plane health data.
type ControlPlaneCollector struct {
	client *client.IstioClient
}

func NewControlPlaneCollector(c *client.IstioClient) *ControlPlaneCollector {
	return &ControlPlaneCollector{client: c}
}

// Collect gathers full control plane status.
func (c *ControlPlaneCollector) Collect(ctx context.Context) (*ControlPlaneStatus, error) {
	status := &ControlPlaneStatus{CollectedAt: time.Now()}

	// Collect istiod pod statuses
	if err := c.collectIstiodPods(ctx, status); err != nil {
		return nil, fmt.Errorf("collect istiod pods: %w", err)
	}

	// Try to get a running istiod pod for debug endpoint queries
	istiodPod, err := c.client.GetIstiodPod(ctx)
	if err != nil {
		return status, nil // Return what we have
	}

	// Port forward to istiod debug port (15014)
	pf, err := c.client.PortForward(ctx, istiodPod.Namespace, istiodPod.Name, 8080)
	if err != nil {
		// Fall back to collecting from istioctl-compatible data
		return status, nil
	}
	defer close(pf.StopChan)

	baseURL := fmt.Sprintf("http://localhost:%d", pf.LocalPort)

	// Collect sync status
	if err := c.collectSyncStatus(ctx, baseURL, status); err != nil {
		// Non-fatal
		fmt.Printf("warn: collect sync status: %v\n", err)
	}

	// Collect push status
	if ps, err := c.collectPushStatus(ctx, baseURL); err == nil {
		status.PushStatus = ps
	}

	// Collect version info
	if vi, err := c.collectVersionInfo(ctx, baseURL); err == nil {
		status.VersionInfo = vi
	}

	return status, nil
}

func (c *ControlPlaneCollector) collectIstiodPods(ctx context.Context, status *ControlPlaneStatus) error {
	pods, err := c.client.K8s.CoreV1().Pods("istio-system").List(ctx, metav1.ListOptions{
		LabelSelector: "app=istiod",
	})
	if err != nil {
		return err
	}

	for _, pod := range pods.Items {
		ps := IstiodPodStatus{
			Name:  pod.Name,
			Phase: pod.Status.Phase,
			Age:   time.Since(pod.CreationTimestamp.Time),
		}

		// Check readiness
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady {
				ps.Ready = cond.Status == corev1.ConditionTrue
			}
		}

		// Restart count
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Name == "discovery" {
				ps.RestartCount = cs.RestartCount
			}
		}

		// Resource requests/limits
		for _, container := range pod.Spec.Containers {
			if container.Name == "discovery" {
				if container.Resources.Requests != nil {
					ps.CPURequest = container.Resources.Requests.Cpu().String()
					ps.MemoryRequest = container.Resources.Requests.Memory().String()
				}
				if container.Resources.Limits != nil {
					ps.CPULimit = container.Resources.Limits.Cpu().String()
					ps.MemoryLimit = container.Resources.Limits.Memory().String()
				}
			}
		}

		status.IstiodPods = append(status.IstiodPods, ps)
	}
	return nil
}

// syncz is the response from istiod's /debug/syncz endpoint.
type synczResponse struct {
	Status []struct {
		ProxyID          string `json:"proxy"`
		ProxyVersion     string `json:"proxy_version"`
		IstioVersion     string `json:"istio_version"`
		ClusterSent      string `json:"cluster_sent"`
		ClusterAcked     string `json:"cluster_acked"`
		ListenerSent     string `json:"listener_sent"`
		ListenerAcked    string `json:"listener_acked"`
		RouteSent        string `json:"route_sent"`
		RouteAcked       string `json:"route_acked"`
		EndpointSent     string `json:"endpoint_sent"`
		EndpointAcked    string `json:"endpoint_acked"`
		EndpointPPercent string `json:"endpoint_percent_sent"`
		ClusterID        string `json:"cluster_id"`
	} `json:"status"`
}

func (c *ControlPlaneCollector) collectSyncStatus(ctx context.Context, baseURL string, status *ControlPlaneStatus) error {
	data, err := httpGet(ctx, baseURL+"/debug/syncz")
	if err != nil {
		return err
	}

	var resp synczResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("parse syncz response: %w", err)
	}

	for _, s := range resp.Status {
		parts := strings.SplitN(s.ProxyID, ".", 2)
		podName, ns := s.ProxyID, ""
		if len(parts) == 2 {
			podName = parts[0]
			ns = parts[1]
		}

		syncStatus := determineSyncState(s.ClusterSent, s.ClusterAcked,
			s.ListenerSent, s.ListenerAcked,
			s.RouteSent, s.RouteAcked)

		pss := ProxySyncStatus{
			PodName:        podName,
			Namespace:      ns,
			ClusterID:      s.ClusterID,
			IstioVersion:   s.IstioVersion,
			ClusterStatus:  xdsSyncState(s.ClusterSent, s.ClusterAcked),
			ListenerStatus: xdsSyncState(s.ListenerSent, s.ListenerAcked),
			RouteStatus:    xdsSyncState(s.RouteSent, s.RouteAcked),
			EndpointStatus: xdsSyncState(s.EndpointSent, s.EndpointAcked),
			SyncState:      syncStatus,
		}

		status.SyncStatus = append(status.SyncStatus, pss)
		status.TotalMeshPods++
		switch syncStatus {
		case "SYNCED":
			status.SyncedPodCount++
		case "STALE":
			status.StalePodCount++
		case "ERROR":
			status.ErrorPodCount++
		}
	}
	return nil
}

func determineSyncState(clusterSent, clusterAcked, listenerSent, listenerAcked, routeSent, routeAcked string) string {
	// If any sent version is empty, config hasn't been pushed yet
	if clusterSent == "" && listenerSent == "" {
		return "NOT_SENT"
	}
	// If all acked match sent, fully synced
	if clusterSent == clusterAcked && listenerSent == listenerAcked && routeSent == routeAcked {
		return "SYNCED"
	}
	// Check for errors (acked contains "error" or version mismatch is very large)
	if strings.Contains(clusterAcked, "error") || strings.Contains(listenerAcked, "error") {
		return "ERROR"
	}
	return "STALE"
}

func xdsSyncState(sent, acked string) string {
	if sent == "" {
		return "NOT_SENT"
	}
	if sent == acked {
		return "SYNCED"
	}
	return "STALE"
}

type pushStatusResponse struct {
	LastPushTime     string `json:"last_push_time"`
	LastPushDuration string `json:"last_push_duration"`
	NumProxies       int64  `json:"num_proxies"`
	PendingPush      int64  `json:"pending_push"`
	TotalPushes      int64  `json:"total_pushes"`
	TotalErrors      int64  `json:"total_errors"`
}

func (c *ControlPlaneCollector) collectPushStatus(ctx context.Context, baseURL string) (*PushStatus, error) {
	data, err := httpGet(ctx, baseURL+"/debug/push_status")
	if err != nil {
		return nil, err
	}

	var resp pushStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return &PushStatus{Raw: string(data)}, nil
	}

	ps := &PushStatus{
		TotalPushes:    resp.TotalPushes,
		TotalErrors:    resp.TotalErrors,
		ProxyCount:     resp.NumProxies,
		PendingProxies: resp.PendingPush,
		LastPushDuration: resp.LastPushDuration,
	}
	if t, err := time.Parse(time.RFC3339, resp.LastPushTime); err == nil {
		ps.LastPushTime = t
	}
	return ps, nil
}

type versionResponse struct {
	MeshVersion []struct {
		IstioVersion string `json:"IstioVersion"`
		Info         struct {
			Version string `json:"version"`
		} `json:"Info"`
		ProxyID string `json:"ProxyID"`
	} `json:"meshVersion"`
	ComponentStatuses []struct {
		Component string `json:"component"`
		Info      struct {
			Version string `json:"version"`
		} `json:"info"`
	} `json:"componentStatuses"`
}

func (c *ControlPlaneCollector) collectVersionInfo(ctx context.Context, baseURL string) (*VersionInfo, error) {
	data, err := httpGet(ctx, baseURL+"/debug/connections")
	if err != nil {
		return nil, err
	}

	vi := &VersionInfo{
		DataPlaneVersions: make(map[string]int),
	}

	// Parse version counts
	var connResp []struct {
		Metadata struct {
			IstioVersion string `json:"IstioVersion"`
		} `json:"Metadata"`
	}
	if err := json.Unmarshal(data, &connResp); err == nil {
		for _, conn := range connResp {
			v := conn.Metadata.IstioVersion
			if v == "" {
				v = "unknown"
			}
			vi.DataPlaneVersions[v]++
		}
	}

	vi.MixedVersions = len(vi.DataPlaneVersions) > 1

	// Get istiod version
	infoData, err := httpGet(ctx, baseURL+"/version")
	if err == nil {
		var info struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(infoData, &info) == nil {
			vi.IstiodVersion = info.Version
		}
	}

	return vi, nil
}

// CollectStalePods returns proxies that have been out of sync for longer than threshold.
func (s *ControlPlaneStatus) CollectStalePods(thresholdSeconds float64) []ProxySyncStatus {
	var stale []ProxySyncStatus
	for _, p := range s.SyncStatus {
		if p.SyncState == "STALE" || p.SyncState == "ERROR" {
			if p.StaleSince != nil && *p.StaleSince > thresholdSeconds {
				stale = append(stale, p)
			} else if p.StaleSince == nil {
				stale = append(stale, p)
			}
		}
	}
	return stale
}

// GatewayPodStatus holds state for a gateway pod.
type GatewayPodStatus struct {
	Name      string
	Namespace string
	Type      string // ingress or egress
	Ready     bool
	Phase     corev1.PodPhase
	IP        string
}

// CollectGatewayPods returns ingress and egress gateway pod statuses.
func CollectGatewayPods(ctx context.Context, c *client.IstioClient) ([]GatewayPodStatus, error) {
	var result []GatewayPodStatus

	// Ingress gateways
	ingressPods, err := c.K8s.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "istio=ingressgateway",
	})
	if err == nil {
		for _, pod := range ingressPods.Items {
			result = append(result, GatewayPodStatus{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Type:      "ingress",
				Ready:     isPodReady(&pod),
				Phase:     pod.Status.Phase,
				IP:        pod.Status.PodIP,
			})
		}
	}

	// Also capture any pods with label istio=egressgateway
	egressPods, err := c.K8s.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "istio=egressgateway",
	})
	if err == nil {
		for _, pod := range egressPods.Items {
			result = append(result, GatewayPodStatus{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Type:      "egress",
				Ready:     isPodReady(&pod),
				Phase:     pod.Status.Phase,
				IP:        pod.Status.PodIP,
			})
		}
	}

	return result, nil
}

func isPodReady(pod *corev1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// ParseVersionedInt tries to parse a version string as an integer.
func ParseVersionedInt(s string) int64 {
	v, _ := strconv.ParseInt(strings.TrimPrefix(s, "v"), 10, 64)
	return v
}
