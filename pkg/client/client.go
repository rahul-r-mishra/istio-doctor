package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	versionedclient "istio.io/client-go/pkg/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// Config holds client configuration.
type Config struct {
	Kubeconfig string
	Context    string
	Workers    int
	Timeout    int
}

// IstioClient wraps Kubernetes and Istio clients with helpers.
type IstioClient struct {
	K8s        kubernetes.Interface
	Istio      versionedclient.Interface
	RestConfig *rest.Config
	Workers    int
	Timeout    time.Duration
}

// New creates a new IstioClient.
func New(cfg Config) (*IstioClient, error) {
	restCfg, err := buildRestConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build rest config: %w", err)
	}

	// Tune for large clusters
	restCfg.QPS = 200
	restCfg.Burst = 400
	restCfg.Timeout = time.Duration(cfg.Timeout) * time.Second

	k8s, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("create k8s client: %w", err)
	}

	istio, err := versionedclient.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("create istio client: %w", err)
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = 50
	}

	return &IstioClient{
		K8s:        k8s,
		Istio:      istio,
		RestConfig: restCfg,
		Workers:    workers,
		Timeout:    time.Duration(cfg.Timeout) * time.Second,
	}, nil
}

func buildRestConfig(cfg Config) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cfg.Kubeconfig != "" {
		rules.ExplicitPath = cfg.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if cfg.Context != "" {
		overrides.CurrentContext = cfg.Context
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
}

// PortForwardResult holds a port-forward session.
type PortForwardResult struct {
	LocalPort uint16
	StopChan  chan struct{}
	ReadyChan chan struct{}
}

// PortForward opens a port-forward to a pod and returns the local port.
func (c *IstioClient) PortForward(ctx context.Context, namespace, podName string, remotePort uint16) (*PortForwardResult, error) {
	pod, err := c.K8s.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", namespace, podName, err)
	}
	if pod.Status.Phase != corev1.PodRunning {
		return nil, fmt.Errorf("pod %s/%s is not running (phase: %s)", namespace, podName, pod.Status.Phase)
	}

	url := c.K8s.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("portforward").
		URL()

	transport, upgrader, err := spdy.RoundTripperFor(c.RestConfig)
	if err != nil {
		return nil, fmt.Errorf("create SPDY transport: %w", err)
	}

	stopChan := make(chan struct{})
	readyChan := make(chan struct{})

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, url)
	fw, err := portforward.New(dialer, []string{fmt.Sprintf("0:%d", remotePort)}, stopChan, readyChan, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create port forwarder: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- fw.ForwardPorts()
	}()

	select {
	case <-readyChan:
	case err := <-errCh:
		return nil, fmt.Errorf("port forward failed: %w", err)
	case <-ctx.Done():
		close(stopChan)
		return nil, ctx.Err()
	}

	ports, err := fw.GetPorts()
	if err != nil || len(ports) == 0 {
		close(stopChan)
		return nil, fmt.Errorf("get forwarded ports: %w", err)
	}

	return &PortForwardResult{
		LocalPort: ports[0].Local,
		StopChan:  stopChan,
		ReadyChan: readyChan,
	}, nil
}

// ExecInPod executes a command in a pod container and returns stdout.
func (c *IstioClient) GetPodsByLabel(ctx context.Context, namespace, labelSelector string) ([]corev1.Pod, error) {
	opts := metav1.ListOptions{}
	if labelSelector != "" {
		opts.LabelSelector = labelSelector
	}
	podList, err := c.K8s.CoreV1().Pods(namespace).List(ctx, opts)
	if err != nil {
		return nil, err
	}
	return podList.Items, nil
}

// GetIstioSystemPods returns pods in the istio-system namespace.
func (c *IstioClient) GetIstioSystemPods(ctx context.Context) ([]corev1.Pod, error) {
	pods, err := c.K8s.CoreV1().Pods("istio-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return pods.Items, nil
}

// GetIstiodPod returns the first running istiod pod.
func (c *IstioClient) GetIstiodPod(ctx context.Context) (*corev1.Pod, error) {
	pods, err := c.K8s.CoreV1().Pods("istio-system").List(ctx, metav1.ListOptions{
		LabelSelector: "app=istiod",
	})
	if err != nil {
		return nil, err
	}
	for i, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning {
			return &pods.Items[i], nil
		}
	}
	return nil, fmt.Errorf("no running istiod pod found in istio-system")
}

// IsSidecarInjected checks if a pod has an istio-proxy sidecar.
func IsSidecarInjected(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == "istio-proxy" {
			return true
		}
	}
	return false
}

// GetWorkloadIdentity returns the SPIFFE identity for a pod's service account.
func GetWorkloadIdentity(pod *corev1.Pod) string {
	sa := pod.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	ns := pod.Namespace
	// Extract trust domain from annotation if present
	trustDomain := "cluster.local"
	if td, ok := pod.Annotations["istio.io/trust-domain"]; ok {
		trustDomain = td
	}
	return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, ns, sa)
}

// NamespaceFilter returns a namespace for listing; empty string means all namespaces.
func NamespaceFilter(ns string) string {
	return ns
}

// FindPodByName finds a pod matching namespace/name or namespace/label=value pattern.
func (c *IstioClient) FindPodByName(ctx context.Context, namespaceAndName string) (*corev1.Pod, error) {
	parts := strings.SplitN(namespaceAndName, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("expected namespace/podname, got: %s", namespaceAndName)
	}
	ns, name := parts[0], parts[1]
	// Try direct name first
	pod, err := c.K8s.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return pod, nil
	}
	// Try as label selector
	pods, err := c.K8s.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", name),
	})
	if err != nil {
		return nil, err
	}
	for i, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning {
			return &pods.Items[i], nil
		}
	}
	return nil, fmt.Errorf("pod not found: %s", namespaceAndName)
}
