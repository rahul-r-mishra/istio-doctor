package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/istio-doctor/pkg/analyzer"
	"github.com/istio-doctor/pkg/collector"
	"github.com/istio-doctor/pkg/output"
)

var (
	staleSyncThreshold float64
	checkTarget        string
)

var checkCmd = &cobra.Command{
	Use:   "check [controlplane|gateway|dataplane|config|all]",
	Short: "Run targeted health checks on Istio components",
	Long: `Run deep health checks on specific Istio components.

Subcommands:
  controlplane  Validate istiod health, xDS sync, push latency
  gateway       Validate ingress/egress gateway configuration
  dataplane     Check proxy sync state, version skew, circuit breakers
  config        Analyze VirtualServices, DestinationRules, AuthZ policies
  all           Run all checks (default)`,
	Example: `  # Check everything
  istio-doctor check

  # Check control plane only
  istio-doctor check controlplane

  # Check gateway configurations
  istio-doctor check gateway

  # Check with custom stale threshold (seconds)
  istio-doctor check dataplane --stale-threshold 60

  # Scope to a namespace
  istio-doctor check config -n payments`,
	Args: cobra.MaximumNArgs(1),
	RunE: runCheck,
}

func init() {
	checkCmd.Flags().Float64Var(&staleSyncThreshold, "stale-threshold", 30.0,
		"Seconds after which a proxy is considered stale (default: 30)")
}

func runCheck(cmd *cobra.Command, args []string) error {
	target := "all"
	if len(args) > 0 {
		target = args[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	report := &output.Report{
		Title:     fmt.Sprintf("Istio Health Check - %s", target),
		Timestamp: time.Now(),
	}
	start := time.Now()

	switch target {
	case "controlplane", "cp":
		if err := checkControlPlane(ctx, report); err != nil {
			return err
		}
	case "gateway", "gw":
		if err := checkGateways(ctx, report); err != nil {
			return err
		}
	case "dataplane", "dp":
		if err := checkDataPlane(ctx, report); err != nil {
			return err
		}
	case "config":
		if err := checkConfig(ctx, report); err != nil {
			return err
		}
	default: // all
		if err := checkControlPlane(ctx, report); err != nil {
			Logger.Warnf("Control plane check error: %v", err)
		}
		if err := checkGateways(ctx, report); err != nil {
			Logger.Warnf("Gateway check error: %v", err)
		}
		if err := checkDataPlane(ctx, report); err != nil {
			Logger.Warnf("Data plane check error: %v", err)
		}
		if err := checkConfig(ctx, report); err != nil {
			Logger.Warnf("Config check error: %v", err)
		}
	}

	report.Duration = time.Since(start).Round(time.Millisecond).String()

	formatter := output.New(outputFmt)
	formatter.PrintReport(report)

	// Exit with non-zero if critical/errors found
	if report.Summary.Critical > 0 || report.Summary.Errors > 0 {
		return fmt.Errorf("found %d critical, %d error findings", report.Summary.Critical, report.Summary.Errors)
	}
	return nil
}

func checkControlPlane(ctx context.Context, report *output.Report) error {
	cpCollector := collector.NewControlPlaneCollector(Client)
	cpStatus, err := cpCollector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect control plane: %w", err)
	}

	// --- Istiod pod health ---
	if len(cpStatus.IstiodPods) == 0 {
		report.AddFinding(output.Finding{
			ID:          "CP001",
			Severity:    output.SeverityCritical,
			Category:    "control-plane",
			Resource:    "istiod",
			Namespace:   "istio-system",
			Message:     "No istiod pods found in istio-system namespace",
			Remediation: "kubectl get deployment istiod -n istio-system && kubectl get pods -n istio-system",
		})
		return nil
	}

	readyCount := 0
	for _, pod := range cpStatus.IstiodPods {
		if pod.Ready {
			readyCount++
		}

		if !pod.Ready {
			report.AddFinding(output.Finding{
				ID:          "CP002",
				Severity:    output.SeverityError,
				Category:    "control-plane",
				Resource:    fmt.Sprintf("pod/%s", pod.Name),
				Namespace:   "istio-system",
				Message:     fmt.Sprintf("Istiod pod '%s' is not ready (phase: %s)", pod.Name, pod.Phase),
				Remediation: fmt.Sprintf("kubectl describe pod %s -n istio-system && kubectl logs %s -n istio-system", pod.Name, pod.Name),
			})
		}

		if pod.RestartCount > 5 {
			report.AddFinding(output.Finding{
				ID:       "CP003",
				Severity: output.SeverityWarning,
				Category: "control-plane",
				Resource: fmt.Sprintf("pod/%s", pod.Name),
				Namespace: "istio-system",
				Message:   fmt.Sprintf("Istiod pod '%s' has restarted %d times", pod.Name, pod.RestartCount),
				Remediation: fmt.Sprintf("kubectl logs %s -n istio-system --previous", pod.Name),
			})
		}
	}

	if readyCount == len(cpStatus.IstiodPods) {
		report.AddFinding(output.Finding{
			ID:       "CP000",
			Severity: output.SeverityPass,
			Category: "control-plane",
			Resource: "istiod",
			Namespace: "istio-system",
			Message:   fmt.Sprintf("All %d istiod pods are ready", readyCount),
		})
	}

	// --- xDS sync status ---
	if cpStatus.TotalMeshPods > 0 {
		syncPct := (cpStatus.SyncedPodCount * 100) / cpStatus.TotalMeshPods

		if cpStatus.StalePodCount > 0 {
			severity := output.SeverityWarning
			if cpStatus.StalePodCount > cpStatus.TotalMeshPods/10 { // >10% stale
				severity = output.SeverityError
			}
			report.AddFinding(output.Finding{
				ID:          "CP010",
				Severity:    severity,
				Category:    "xds-sync",
				Resource:    "data-plane",
				Message:     fmt.Sprintf("%d proxies are STALE (%d%% in sync). Stale proxies may have outdated routing rules.", cpStatus.StalePodCount, syncPct),
				Remediation: "Check istiod logs for push errors: kubectl logs -l app=istiod -n istio-system --tail=100",
			})
		}

		if cpStatus.ErrorPodCount > 0 {
			report.AddFinding(output.Finding{
				ID:          "CP011",
				Severity:    output.SeverityError,
				Category:    "xds-sync",
				Resource:    "data-plane",
				Message:     fmt.Sprintf("%d proxies have ERROR sync state", cpStatus.ErrorPodCount),
				Remediation: "Identify error pods: istio-doctor check dataplane --stale-threshold 0",
			})
		}

		if cpStatus.StalePodCount == 0 && cpStatus.ErrorPodCount == 0 {
			report.AddFinding(output.Finding{
				ID:       "CP009",
				Severity: output.SeverityPass,
				Category: "xds-sync",
				Resource: "data-plane",
				Message:   fmt.Sprintf("All %d mesh pods are in sync", cpStatus.TotalMeshPods),
			})
		}
	}

	// --- Push status ---
	if cpStatus.PushStatus != nil && cpStatus.PushStatus.TotalErrors > 0 {
		report.AddFinding(output.Finding{
			ID:          "CP020",
			Severity:    output.SeverityWarning,
			Category:    "xds-push",
			Resource:    "istiod",
			Namespace:   "istio-system",
			Message:     fmt.Sprintf("istiod has %d xDS push errors (total pushes: %d)", cpStatus.PushStatus.TotalErrors, cpStatus.PushStatus.TotalPushes),
			Remediation: "kubectl logs -l app=istiod -n istio-system | grep -i 'push error'",
		})
	}

	// --- Version info ---
	if cpStatus.VersionInfo != nil && cpStatus.VersionInfo.MixedVersions {
		versions := []string{}
		for v, count := range cpStatus.VersionInfo.DataPlaneVersions {
			versions = append(versions, fmt.Sprintf("%s(%d)", v, count))
		}
		report.AddFinding(output.Finding{
			ID:          "CP030",
			Severity:    output.SeverityWarning,
			Category:    "version-skew",
			Resource:    "data-plane",
			Message:     fmt.Sprintf("Mixed proxy versions detected: %v", versions),
			Detail:      "Version skew >1 minor version between istiod and proxies can cause undefined behavior",
			Remediation: "Perform rolling restart: kubectl rollout restart deployment -A",
		})
	}

	return nil
}

func checkGateways(ctx context.Context, report *output.Report) error {
	policyCollector := collector.NewPolicyCollector(Client)
	policies, err := policyCollector.Collect(ctx, namespace)
	if err != nil {
		return fmt.Errorf("collect policies: %w", err)
	}

	gwAnalyzer := analyzer.NewGatewayAnalyzer(Client, policies)
	gwReport, err := gwAnalyzer.ValidateAll(ctx)
	if err != nil {
		return fmt.Errorf("validate gateways: %w", err)
	}

	for _, validation := range append(gwReport.IngressGateways, gwReport.EgressGateways...) {
		for _, finding := range validation.Findings {
			report.AddFinding(finding)
		}
	}

	if len(gwReport.IngressGateways)+len(gwReport.EgressGateways) == 0 {
		report.AddFinding(output.Finding{
			ID:       "GW000",
			Severity: output.SeverityInfo,
			Category: "gateway",
			Resource: "cluster",
			Message:  "No Gateway resources found in cluster",
		})
	}

	return nil
}

func checkDataPlane(ctx context.Context, report *output.Report) error {
	proxyCollector := collector.NewProxyCollector(Client)
	opts := collector.DefaultProxyCollectionOptions()
	opts.Concurrency = workers

	proxies, err := proxyCollector.CollectAll(ctx, namespace, opts)
	if err != nil {
		return fmt.Errorf("collect proxies: %w", err)
	}

	if len(proxies) == 0 {
		report.AddFinding(output.Finding{
			ID:       "DP000",
			Severity: output.SeverityInfo,
			Category: "data-plane",
			Resource: "cluster",
			Message:  "No sidecar-injected pods found",
		})
		return nil
	}

	errorCount := 0
	staleCount := 0
	healthyCount := 0
	versionMix := make(map[string]int)

	for _, proxy := range proxies {
		if proxy.Error != "" {
			errorCount++
			report.AddFinding(output.Finding{
				ID:        "DP001",
				Severity:  output.SeverityError,
				Category:  "data-plane",
				Resource:  fmt.Sprintf("pod/%s", proxy.PodName),
				Namespace: proxy.Namespace,
				Message:   fmt.Sprintf("Cannot reach Envoy admin API: %s", proxy.Error),
				Remediation: fmt.Sprintf("kubectl logs %s -n %s -c istio-proxy", proxy.PodName, proxy.Namespace),
			})
			continue
		}

		if proxy.SyncState == "STALE" || proxy.SyncState == "ERROR" {
			staleCount++
			if staleCount <= 20 { // Don't flood report for large clusters
				report.AddFinding(output.Finding{
					ID:        "DP002",
					Severity:  output.SeverityWarning,
					Category:  "data-plane",
					Resource:  fmt.Sprintf("pod/%s", proxy.PodName),
					Namespace: proxy.Namespace,
					Message:   fmt.Sprintf("Proxy sync state: %s", proxy.SyncState),
					Remediation: fmt.Sprintf("kubectl exec %s -n %s -c istio-proxy -- pilot-agent request GET /clusters?format=json", proxy.PodName, proxy.Namespace),
				})
			}
		} else {
			healthyCount++
		}

		if proxy.IstioVersion != "" {
			versionMix[proxy.IstioVersion]++
		}

		// Check for unhealthy clusters
		for _, cluster := range proxy.Clusters {
			if cluster.HealthStatus != "HEALTHY" && cluster.HealthStatus != "" && cluster.EndpointCount > 0 {
				report.AddFinding(output.Finding{
					ID:        "DP010",
					Severity:  output.SeverityWarning,
					Category:  "data-plane",
					Resource:  fmt.Sprintf("pod/%s cluster/%s", proxy.PodName, cluster.Name),
					Namespace: proxy.Namespace,
					Message:   fmt.Sprintf("Cluster '%s' health status: %s (%d endpoints)", cluster.Name, cluster.HealthStatus, cluster.EndpointCount),
				})
			}
		}
	}

	if staleCount > 20 {
		report.AddFinding(output.Finding{
			ID:          "DP003",
			Severity:    output.SeverityWarning,
			Category:    "data-plane",
			Resource:    "cluster",
			Message:     fmt.Sprintf("... and %d more stale proxies (showing first 20)", staleCount-20),
			Remediation: "istio-doctor check controlplane to diagnose istiod push issues",
		})
	}

	if errorCount == 0 && staleCount == 0 {
		report.AddFinding(output.Finding{
			ID:       "DP000",
			Severity: output.SeverityPass,
			Category: "data-plane",
			Resource: "cluster",
			Message:   fmt.Sprintf("All %d proxies are healthy and reachable", healthyCount),
		})
	}

	// Version skew
	if len(versionMix) > 2 {
		report.AddFinding(output.Finding{
			ID:       "DP020",
			Severity: output.SeverityWarning,
			Category: "data-plane",
			Resource: "cluster",
			Message:   fmt.Sprintf("Detected %d distinct proxy versions - large version skew", len(versionMix)),
			Remediation: "kubectl rollout restart deployment -A to upgrade proxies",
		})
	}

	return nil
}

func checkConfig(ctx context.Context, report *output.Report) error {
	policyCollector := collector.NewPolicyCollector(Client)
	policies, err := policyCollector.Collect(ctx, namespace)
	if err != nil {
		return fmt.Errorf("collect policies: %w", err)
	}

	configAnalyzer := analyzer.NewConfigAnalyzer(Client, policies)
	findings := configAnalyzer.Analyze(ctx, namespace)

	for _, f := range findings {
		report.AddFinding(f)
	}

	if len(findings) == 0 {
		report.AddFinding(output.Finding{
			ID:       "CFG000",
			Severity: output.SeverityPass,
			Category: "config",
			Resource: "cluster",
			Message:  "No configuration issues found",
		})
	}

	return nil
}
