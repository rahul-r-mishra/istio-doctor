package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/istio-doctor/pkg/collector"
	"github.com/istio-doctor/pkg/output"
)

var summaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Display a real-time health dashboard of the entire Istio mesh",
	Long: `Collect and display a high-level summary of:
  - Istiod control plane health and xDS push status
  - Ingress and egress gateway pod readiness
  - Data plane proxy sync state across all pods
  - Authorization policy count and warning summary
  - Network policy count

Designed to run in seconds even on 50k+ pod clusters.`,
	Example: `  # Cluster-wide summary
  istio-doctor summary

  # Summary for a specific namespace
  istio-doctor summary -n payments

  # Output as JSON for monitoring
  istio-doctor summary -o json`,
	RunE: runSummary,
}

func runSummary(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	start := time.Now()
	fmt.Println()
	color.New(color.Bold, color.FgCyan).Println("  ▶ Collecting mesh status...")
	fmt.Println()

	// Collect control plane status
	cpCollector := collector.NewControlPlaneCollector(Client)
	cpStatus, err := cpCollector.Collect(ctx)
	if err != nil {
		Logger.Warnf("Control plane collection partial: %v", err)
	}

	// Collect policies
	policyCollector := collector.NewPolicyCollector(Client)
	policies, err := policyCollector.Collect(ctx, namespace)
	if err != nil {
		Logger.Warnf("Policy collection partial: %v", err)
	}

	// Gateway pods
	gatewayPods, _ := collector.CollectGatewayPods(ctx, Client)

	elapsed := time.Since(start)

	// Render dashboard
	printSummaryDashboard(cpStatus, policies, gatewayPods, elapsed)

	return nil
}

func printSummaryDashboard(
	cp *collector.ControlPlaneStatus,
	policies *collector.PolicyCollection,
	gatewayPods []collector.GatewayPodStatus,
	elapsed time.Duration,
) {
	w := output.New(outputFmt)
	_ = w

	fmt.Printf("  Collected in %s  ·  %s\n\n",
		color.CyanString(elapsed.Round(time.Millisecond).String()),
		time.Now().Format("2006-01-02 15:04:05"))

	printSectionHeader("CONTROL PLANE")
	if cp != nil {
		// Istiod pods
		totalIstiod := len(cp.IstiodPods)
		readyIstiod := 0
		for _, pod := range cp.IstiodPods {
			if pod.Ready {
				readyIstiod++
			}
		}
		istiodStatus := color.GreenString("✓")
		if readyIstiod < totalIstiod {
			istiodStatus = color.YellowString("⚠")
		}
		if readyIstiod == 0 {
			istiodStatus = color.RedString("✗")
		}
		output.PrintKeyValue("  Istiod Replicas",
			fmt.Sprintf("%s %d/%d ready", istiodStatus, readyIstiod, totalIstiod))

		// xDS push status
		if cp.PushStatus != nil {
			ps := cp.PushStatus
			pushAge := ""
			if !ps.LastPushTime.IsZero() {
				pushAge = fmt.Sprintf(" (last: %s ago)", time.Since(ps.LastPushTime).Round(time.Second))
			}
			output.PrintKeyValue("  xDS Pushes",
				fmt.Sprintf("Total: %d  Errors: %s  Pending: %d%s",
					ps.TotalPushes,
					errorCount(ps.TotalErrors),
					ps.PendingProxies,
					pushAge))
			if ps.LastPushDuration != "" {
				output.PrintKeyValue("  Last Push Duration", ps.LastPushDuration)
			}
		}

		// Version info
		if cp.VersionInfo != nil {
			vi := cp.VersionInfo
			if vi.IstiodVersion != "" {
				output.PrintKeyValue("  Istiod Version", vi.IstiodVersion)
			}
			if vi.MixedVersions {
				versionList := []string{}
				for v, count := range vi.DataPlaneVersions {
					versionList = append(versionList, fmt.Sprintf("%s×%d", v, count))
				}
				output.PrintKeyValue("  Data Plane Versions",
					color.YellowString("⚠ MIXED: "+strings.Join(versionList, ", ")))
			} else {
				for v := range vi.DataPlaneVersions {
					output.PrintKeyValue("  Data Plane Version", v)
					break
				}
			}
		}
	}

	fmt.Println()
	printSectionHeader("DATA PLANE")
	if cp != nil {
		total := cp.TotalMeshPods
		synced := cp.SyncedPodCount
		stale := cp.StalePodCount
		errCount := cp.ErrorPodCount
		notSent := total - synced - stale - errCount

		syncPct := 0
		if total > 0 {
			syncPct = (synced * 100) / total
		}

		syncColor := color.GreenString
		if syncPct < 95 {
			syncColor = color.YellowString
		}
		if syncPct < 80 {
			syncColor = color.RedString
		}

		output.PrintKeyValue("  Mesh Pods", fmt.Sprintf("%d total", total))
		output.PrintKeyValue("  Sync Status",
			fmt.Sprintf("%s  %s  %s  %s",
				syncColor(fmt.Sprintf("✓ SYNCED: %d (%d%%)", synced, syncPct)),
				color.YellowString(fmt.Sprintf("⚠ STALE: %d", stale)),
				color.RedString(fmt.Sprintf("✗ ERROR: %d", errCount)),
				color.CyanString(fmt.Sprintf("○ NOT_SENT: %d", notSent)),
			))
	}

	fmt.Println()
	printSectionHeader("GATEWAYS")
	ingressPods := filterGatewayPods(gatewayPods, "ingress")
	egressPods := filterGatewayPods(gatewayPods, "egress")

	if len(ingressPods) == 0 && len(egressPods) == 0 {
		output.PrintInfo("No gateway pods found")
	}

	if len(ingressPods) > 0 {
		ready, total := countReadyGatewayPods(ingressPods)
		statusIcon := readinessIcon(ready, total)
		output.PrintKeyValue("  Ingress Gateways",
			fmt.Sprintf("%s %d/%d pods ready  (namespaces: %s)",
				statusIcon, ready, total, gatewayNamespaces(ingressPods)))
	}
	if len(egressPods) > 0 {
		ready, total := countReadyGatewayPods(egressPods)
		statusIcon := readinessIcon(ready, total)
		output.PrintKeyValue("  Egress Gateways",
			fmt.Sprintf("%s %d/%d pods ready  (namespaces: %s)",
				statusIcon, ready, total, gatewayNamespaces(egressPods)))
	}

	fmt.Println()
	printSectionHeader("POLICIES")
	if policies != nil {
		summary := policies.Summary()
		output.PrintKeyValue("  AuthorizationPolicies", fmt.Sprintf("%d", summary["authorization_policies"]))
		output.PrintKeyValue("  PeerAuthentications",   fmt.Sprintf("%d", summary["peer_authentications"]))
		output.PrintKeyValue("  NetworkPolicies",       fmt.Sprintf("%d", summary["network_policies"]))
		output.PrintKeyValue("  VirtualServices",       fmt.Sprintf("%d", summary["virtual_services"]))
		output.PrintKeyValue("  DestinationRules",      fmt.Sprintf("%d", summary["destination_rules"]))
		output.PrintKeyValue("  Gateways",              fmt.Sprintf("%d", summary["gateways"]))
		output.PrintKeyValue("  ServiceEntries",        fmt.Sprintf("%d", summary["service_entries"]))
		output.PrintKeyValue("  Sidecars",              fmt.Sprintf("%d", summary["sidecars"]))
		output.PrintKeyValue("  EnvoyFilters",          fmt.Sprintf("%d", summary["envoy_filters"]))

		// Quick authz policy sanity check
		emptyRuleCount := 0
		for _, ap := range policies.AuthorizationPolicies {
			if len(ap.Spec.GetRules()) == 0 && ap.Spec.GetAction().String() == "ALLOW" {
				emptyRuleCount++
			}
		}
		if emptyRuleCount > 0 {
			output.PrintKeyValue("  ⚠ AuthZ Warnings",
				color.YellowString(fmt.Sprintf("%d ALLOW policies with empty rules (deny-all footgun!)", emptyRuleCount)))
		}
	}

	fmt.Println()
	printSectionHeader("QUICK CHECKS")
	fmt.Printf("  Run %s for deep analysis\n", color.CyanString("istio-doctor check"))
	fmt.Printf("  Run %s to trace a traffic path\n", color.CyanString("istio-doctor trace --from ns/pod --to ns/svc:port"))
	fmt.Printf("  Run %s for AuthZ audit\n", color.CyanString("istio-doctor audit authz"))
	fmt.Println()
}

func printSectionHeader(title string) {
	fmt.Printf("  %s\n", color.New(color.Bold, color.FgWhite).Sprintf(title))
	fmt.Printf("  %s\n", strings.Repeat("─", 50))
}

func filterGatewayPods(pods []collector.GatewayPodStatus, gwType string) []collector.GatewayPodStatus {
	var result []collector.GatewayPodStatus
	for _, pod := range pods {
		if pod.Type == gwType {
			result = append(result, pod)
		}
	}
	return result
}

func countReadyGatewayPods(pods []collector.GatewayPodStatus) (int, int) {
	ready := 0
	for _, pod := range pods {
		if pod.Ready {
			ready++
		}
	}
	return ready, len(pods)
}

func readinessIcon(ready, total int) string {
	if total == 0 {
		return color.YellowString("?")
	}
	if ready == total {
		return color.GreenString("✓")
	}
	if ready == 0 {
		return color.RedString("✗")
	}
	return color.YellowString("⚠")
}

func gatewayNamespaces(pods []collector.GatewayPodStatus) string {
	seen := make(map[string]bool)
	var ns []string
	for _, pod := range pods {
		if !seen[pod.Namespace] {
			seen[pod.Namespace] = true
			ns = append(ns, pod.Namespace)
		}
	}
	return strings.Join(ns, ", ")
}

func errorCount(n int64) string {
	if n == 0 {
		return color.GreenString("0")
	}
	return color.RedString(fmt.Sprintf("%d", n))
}
