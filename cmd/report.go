package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/istio-doctor/pkg/analyzer"
	"github.com/istio-doctor/pkg/collector"
	"github.com/istio-doctor/pkg/output"
)

var (
	reportOutputFile string
	reportFormat     string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a comprehensive Istio health report",
	Long: `Generate a full mesh health report combining all checks:
  - Control plane health
  - Gateway validation
  - Data plane proxy status
  - Configuration analysis
  - Authorization policy audit

Output to file in JSON or table format for archiving or CI pipelines.`,
	Example: `  # Full report to stdout
  istio-doctor report

  # JSON report to file
  istio-doctor report -o json --out-file /tmp/mesh-report.json

  # Scoped to namespace
  istio-doctor report -n payments -o json`,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportOutputFile, "out-file", "",
		"Write report to file (default: stdout)")
}

func runReport(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*2*time.Second)
	defer cancel()

	start := time.Now()

	color.New(color.Bold, color.FgCyan).Printf("\n  ▶ Generating full mesh report...\n\n")

	report := &output.Report{
		Title:     "Istio Mesh Full Health Report",
		Timestamp: time.Now(),
	}

	// Collect everything
	fmt.Printf("  [1/5] Control plane health...\n")
	if err := checkControlPlane(ctx, report); err != nil {
		fmt.Printf("    warn: %v\n", err)
	}

	fmt.Printf("  [2/5] Gateway validation...\n")
	if err := checkGateways(ctx, report); err != nil {
		fmt.Printf("    warn: %v\n", err)
	}

	fmt.Printf("  [3/5] Data plane proxy status...\n")
	if err := checkDataPlane(ctx, report); err != nil {
		fmt.Printf("    warn: %v\n", err)
	}

	fmt.Printf("  [4/5] Configuration analysis...\n")
	if err := checkConfig(ctx, report); err != nil {
		fmt.Printf("    warn: %v\n", err)
	}

	fmt.Printf("  [5/5] Authorization policy audit...\n")
	policyCollector := collector.NewPolicyCollector(Client)
	policies, err := policyCollector.Collect(ctx, namespace)
	if err == nil {
		authzAnalyzer := analyzer.NewAuthzAnalyzer("cluster.local")
		auditResult := authzAnalyzer.AuditPolicies(policies.AuthorizationPolicies)
		for _, f := range auditResult.Findings {
			report.AddFinding(output.Finding{
				ID:          "AUTHZ-" + f.PolicyName,
				Severity:    severityFromString(f.Severity),
				Category:    "authz-audit",
				Resource:    fmt.Sprintf("authorizationpolicy/%s", f.PolicyName),
				Namespace:   f.Namespace,
				Message:     f.Description,
				Remediation: f.Remediation,
			})
		}
	}

	report.Duration = time.Since(start).Round(time.Millisecond).String()

	fmt.Println()

	// Output
	var formatter *output.Formatter
	if reportOutputFile != "" {
		f, err := os.Create(reportOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		formatter = &output.Formatter{Format: outputFmt, Writer: f}
		defer func() {
			color.GreenString("  ✓ Report written to %s\n", reportOutputFile)
		}()
	} else {
		formatter = output.New(outputFmt)
	}

	formatter.PrintReport(report)

	if reportOutputFile != "" {
		fmt.Printf("\n  %s Report written to: %s\n\n",
			color.GreenString("✓"), reportOutputFile)
	}

	return nil
}

func severityFromString(s string) output.Severity {
	switch s {
	case "CRITICAL":
		return output.SeverityCritical
	case "ERROR":
		return output.SeverityError
	case "WARN":
		return output.SeverityWarning
	case "INFO":
		return output.SeverityInfo
	default:
		return output.SeverityInfo
	}
}
