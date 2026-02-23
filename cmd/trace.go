package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/istio-doctor/pkg/analyzer"
	"github.com/istio-doctor/pkg/collector"
)

var (
	traceFrom        string
	traceTo          string
	tracePath        string
	traceMethod      string
	traceEgress      bool
)

var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "Trace and analyze a traffic path end-to-end",
	Long: `Trace the complete traffic path from a source pod to a destination.

Checks at each hop:
  1. Source pod sidecar health and sync state
  2. Sidecar CR egress restrictions
  3. NetworkPolicy egress rules
  4. AuthorizationPolicy (source → egress gateway if applicable)
  5. Egress gateway configuration (Gateway CR, VirtualService, DestinationRule)
  6. ServiceEntry for external destinations
  7. AuthorizationPolicy (source → destination service)
  8. Destination service and endpoint health

Each hop reports PASS / WARN / FAIL with the exact resource causing issues.`,
	Example: `  # Trace internal service-to-service traffic
  istio-doctor trace --from payments/checkout-7d9c8f-xyz --to payments/orders-api:8080

  # Trace external traffic through egress gateway
  istio-doctor trace --from payments/checkout-7d9c8f-xyz --to api.stripe.com:443 --egress

  # Trace with specific HTTP method and path
  istio-doctor trace --from ns/pod --to ns/svc:8080 --path /api/orders --method POST`,
	RunE: runTrace,
}

func init() {
	traceCmd.Flags().StringVar(&traceFrom, "from", "", "Source: namespace/pod-name (required)")
	traceCmd.Flags().StringVar(&traceTo, "to", "", "Destination: namespace/service:port or external-host:port (required)")
	traceCmd.Flags().StringVar(&tracePath, "path", "/", "HTTP path for AuthZ evaluation (default: /)")
	traceCmd.Flags().StringVar(&traceMethod, "method", "GET", "HTTP method for AuthZ evaluation")
	traceCmd.Flags().BoolVar(&traceEgress, "egress", false, "Force route through egress gateway for external destinations")
	traceCmd.MarkFlagRequired("from")
	traceCmd.MarkFlagRequired("to")
}

func runTrace(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// Collect all policies
	policyCollector := collector.NewPolicyCollector(Client)
	policies, err := policyCollector.Collect(ctx, "")
	if err != nil {
		return fmt.Errorf("collect policies: %w", err)
	}

	connAnalyzer := analyzer.NewConnectivityAnalyzer(Client, policies)

	req := &analyzer.TraceRequest{
		FromPod:          traceFrom,
		ToDestination:    traceTo,
		Path:             tracePath,
		Method:           traceMethod,
		UseEgressGateway: traceEgress,
		TrustDomain:      "cluster.local",
	}

	fmt.Printf("\n  Tracing: %s → %s\n", color.CyanString(traceFrom), color.CyanString(traceTo))
	fmt.Printf("  Method: %s %s\n\n", traceMethod, tracePath)

	result, err := connAnalyzer.Trace(ctx, req)
	if err != nil {
		return fmt.Errorf("trace failed: %w", err)
	}

	printTraceResult(result)
	return nil
}

func printTraceResult(result *analyzer.TraceResult) {
	// Print each hop
	for i, hop := range result.Hops {
		connector := "│"
		if i == 0 {
			connector = " "
		}
		_ = connector

		// Hop header
		statusIcon := hopStatusIcon(hop.Status)
		fmt.Printf("  %s %s\n", statusIcon, color.New(color.Bold).Sprint(hop.Name))

		// Resources involved
		if len(hop.Resources) > 0 {
			fmt.Printf("    %s %s\n", color.New(color.Faint).Sprint("resources:"), strings.Join(hop.Resources, ", "))
		}

		// Description
		if hop.Description != "" {
			fmt.Printf("    %s\n", hop.Description)
		}

		// Issues
		for _, issue := range hop.Issues {
			switch issue.Severity {
			case "ERROR":
				fmt.Printf("    %s %s\n", color.RedString("✗"), issue.Description)
				if issue.Remediation != "" {
					fmt.Printf("      %s %s\n", color.CyanString("→"), issue.Remediation)
				}
			case "WARN":
				fmt.Printf("    %s %s\n", color.YellowString("⚠"), issue.Description)
				if issue.Remediation != "" {
					fmt.Printf("      %s %s\n", color.CyanString("→"), issue.Remediation)
				}
			case "INFO":
				fmt.Printf("    %s %s\n", color.CyanString("ℹ"), issue.Description)
			}
		}

		// Arrow to next hop
		if i < len(result.Hops)-1 {
			if hop.Status == "FAIL" {
				fmt.Printf("\n  %s\n\n", color.RedString("✗ BLOCKED HERE"))
				break
			}
			fmt.Printf("  %s\n", color.New(color.Faint).Sprint("  ↓"))
		}
		fmt.Println()
	}

	// Verdict
	fmt.Printf("  %s\n", strings.Repeat("─", 50))
	switch result.Verdict {
	case "ALLOWED":
		fmt.Printf("  %s Traffic should be ALLOWED end-to-end\n\n",
			color.GreenString("✓ VERDICT:"))
	case "BLOCKED":
		fmt.Printf("  %s Traffic BLOCKED at: %s\n\n",
			color.RedString("✗ VERDICT:"),
			color.RedString(result.BlockedAt))
	case "LIKELY_ALLOWED_WITH_WARNINGS":
		fmt.Printf("  %s Traffic likely allowed but warnings need review\n\n",
			color.YellowString("⚠ VERDICT:"))
	default:
		fmt.Printf("  %s %s\n\n", color.YellowString("? VERDICT:"), result.Verdict)
	}

	// Summary actions
	if len(result.Summary) > 0 {
		fmt.Printf("  %s\n", color.New(color.Bold).Sprint("Recommended Actions:"))
		for _, s := range result.Summary {
			fmt.Printf("  %s\n", s)
		}
		fmt.Println()
	}
}

func hopStatusIcon(status string) string {
	switch status {
	case "PASS":
		return color.GreenString("  ✓")
	case "WARN":
		return color.YellowString("  ⚠")
	case "FAIL":
		return color.RedString("  ✗")
	default:
		return color.CyanString("  ?")
	}
}
