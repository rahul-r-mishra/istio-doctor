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
	"github.com/istio-doctor/pkg/output"
)

var (
	auditFromPrincipal string
	auditToService     string
	auditToPort        uint32
	auditToPath        string
	auditToMethod      string
)

var auditCmd = &cobra.Command{
	Use:   "audit [authz|policies|all]",
	Short: "Audit Istio policies for misconfigurations and security issues",
	Long: `Audit Istio authorization policies and related configurations.

Modes:
  authz    Audit AuthorizationPolicies for misconfigurations
  policies Audit all mesh policies (VirtualService, DestinationRule, etc.)
  all      Run all audits (default)

When --from and --to-service are specified, evaluates specific traffic against policies.`,
	Example: `  # Audit all authz policies in cluster
  istio-doctor audit authz

  # Audit policies in a specific namespace
  istio-doctor audit authz -n payments

  # Evaluate specific traffic: can checkout reach orders-api?
  istio-doctor audit authz \
    --from spiffe://cluster.local/ns/payments/sa/checkout \
    --to-service orders-api --to-port 8080 \
    --to-path /api/orders --to-method POST`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAudit,
}

func init() {
	auditCmd.Flags().StringVar(&auditFromPrincipal, "from", "",
		"Source SPIFFE URI (e.g., spiffe://cluster.local/ns/payments/sa/checkout)")
	auditCmd.Flags().StringVar(&auditToService, "to-service", "",
		"Destination service name")
	auditCmd.Flags().Uint32Var(&auditToPort, "to-port", 80,
		"Destination port")
	auditCmd.Flags().StringVar(&auditToPath, "to-path", "/",
		"Destination HTTP path")
	auditCmd.Flags().StringVar(&auditToMethod, "to-method", "GET",
		"HTTP method")
}

func runAudit(cmd *cobra.Command, args []string) error {
	target := "all"
	if len(args) > 0 {
		target = args[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	policyCollector := collector.NewPolicyCollector(Client)
	policies, err := policyCollector.Collect(ctx, namespace)
	if err != nil {
		return fmt.Errorf("collect policies: %w", err)
	}

	switch target {
	case "authz":
		return runAuthzAuditFull(ctx, policies)
	case "policies":
		return runFullPolicyAudit(ctx, policies)
	default:
		if err := runAuthzAuditFull(ctx, policies); err != nil {
			return err
		}
		return runFullPolicyAudit(ctx, policies)
	}
}

func runAuthzAuditFull(ctx context.Context, policies *collector.PolicyCollection) error {
	authzAnalyzer := analyzer.NewAuthzAnalyzer("cluster.local")

	// Specific traffic evaluation mode
	if auditFromPrincipal != "" && auditToService != "" {
		return runSpecificTrafficEval(authzAnalyzer, policies)
	}

	// Static audit of all policies
	fmt.Printf("\n  Auditing %d AuthorizationPolicies...\n\n", len(policies.AuthorizationPolicies))

	auditResult := authzAnalyzer.AuditPolicies(policies.AuthorizationPolicies)

	// Statistics
	printSectionHeader("STATISTICS")
	output.PrintKeyValue("  Total Policies",        fmt.Sprintf("%d", auditResult.Statistics.TotalPolicies))
	output.PrintKeyValue("  ALLOW Policies",        fmt.Sprintf("%d", auditResult.Statistics.AllowPolicies))
	output.PrintKeyValue("  DENY Policies",         fmt.Sprintf("%d", auditResult.Statistics.DenyPolicies))
	output.PrintKeyValue("  Empty-Rule (DENY-ALL)", severityCountStr(auditResult.Statistics.EmptyRulePolicies, "CRITICAL"))
	output.PrintKeyValue("  No Selector (Broad)",   severityCountStr(auditResult.Statistics.MissingSelectors, "WARN"))
	output.PrintKeyValue("  Principal Typos",       severityCountStr(auditResult.Statistics.PotentialTypos, "ERROR"))
	fmt.Println()

	if len(auditResult.Findings) == 0 {
		output.PrintSuccess("No AuthorizationPolicy misconfigurations found")
		fmt.Println()
		return nil
	}

	// Group findings by severity
	bySeverity := map[string][]analyzer.AuthzFinding{}
	for _, f := range auditResult.Findings {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	for _, sev := range []string{"CRITICAL", "ERROR", "WARN", "INFO"} {
		findings := bySeverity[sev]
		if len(findings) == 0 {
			continue
		}

		printSectionHeader(fmt.Sprintf("%s (%d)", sev, len(findings)))
		for _, f := range findings {
			icon := findingSeverityIcon(f.Severity)
			fmt.Printf("  %s %s/%s\n", icon, f.Namespace, f.PolicyName)
			fmt.Printf("    %s\n", f.Description)
			if f.Remediation != "" {
				fmt.Printf("    %s %s\n\n", color.CyanString("→"), f.Remediation)
			} else {
				fmt.Println()
			}
		}
	}

	// Namespace breakdown
	printSectionHeader("NAMESPACE BREAKDOWN")
	nsFindings := make(map[string]int)
	for _, f := range auditResult.Findings {
		nsFindings[f.Namespace]++
	}
	for ns, count := range nsFindings {
		output.PrintKeyValue(fmt.Sprintf("  %s", ns), fmt.Sprintf("%d issues", count))
	}
	fmt.Println()

	return nil
}

func runSpecificTrafficEval(authzAnalyzer *analyzer.AuthzAnalyzer, policies *collector.PolicyCollection) error {
	fmt.Printf("\n  Evaluating traffic:\n")
	fmt.Printf("  From: %s\n", color.CyanString(auditFromPrincipal))
	fmt.Printf("  To:   %s:%d%s [%s]\n\n",
		color.CyanString(auditToService), auditToPort, auditToPath, auditToMethod)

	// Parse principal to extract namespace and SA
	srcNS, srcSA := parsePrincipal(auditFromPrincipal)

	req := &analyzer.TrafficRequest{
		SourceNamespace:      srcNS,
		SourceServiceAccount: srcSA,
		SourcePrincipal:      auditFromPrincipal,
		DestNamespace:        namespace,
		DestService:          auditToService,
		DestPort:             auditToPort,
		DestPath:             auditToPath,
		Method:               auditToMethod,
	}

	decision := authzAnalyzer.Evaluate(req, policies.AuthorizationPolicies)

	// Display decision
	printSectionHeader("EVALUATION RESULT")
	if decision.Allowed {
		output.PrintSuccess(fmt.Sprintf("Traffic ALLOWED: %s", decision.Reason))
	} else {
		output.PrintError(fmt.Sprintf("Traffic DENIED: %s", decision.Reason))
	}

	if decision.MatchedPolicy != "" {
		output.PrintKeyValue("  Matched Policy", decision.MatchedPolicy)
		output.PrintKeyValue("  Matched Rule",   fmt.Sprintf("%d", decision.MatchedRule))
	}
	fmt.Println()

	// Show DENY policy matches
	if len(decision.DenyPolicies) > 0 {
		printSectionHeader("DENY POLICY MATCHES")
		for _, dm := range decision.DenyPolicies {
			fmt.Printf("  %s %s/%s (rule[%d]): %s\n",
				color.RedString("✗"), dm.PolicyNamespace, dm.PolicyName, dm.RuleIndex, dm.MatchReason)
		}
		fmt.Println()
	}

	// Show ALLOW policy matches/mismatches
	if len(decision.AllowPolicies) > 0 {
		printSectionHeader("ALLOW POLICY EVALUATION")
		for _, am := range decision.AllowPolicies {
			if am.Action == "ALLOW" && am.MatchReason != "Empty rules - denies all traffic" {
				fmt.Printf("  %s %s/%s (rule[%d]): %s\n",
					color.GreenString("✓"), am.PolicyNamespace, am.PolicyName, am.RuleIndex, am.MatchReason)
			} else {
				fmt.Printf("  %s %s/%s: %s\n",
					color.RedString("!"), am.PolicyNamespace, am.PolicyName, am.MatchReason)
			}
		}
		fmt.Println()
	}

	// Warnings and near-misses
	if len(decision.Warnings) > 0 {
		printSectionHeader("WARNINGS & NEAR-MISSES")
		for _, w := range decision.Warnings {
			fmt.Printf("  %s %s\n", color.YellowString("⚠"), w)
		}
		fmt.Println()
	}

	// Suggest remediation if denied
	if !decision.Allowed {
		printSectionHeader("SUGGESTED REMEDIATION")
		fmt.Printf("  If this traffic should be allowed, create an AuthorizationPolicy:\n\n")
		printAuthzPolicySuggestion(req)
	}

	return nil
}

func runFullPolicyAudit(ctx context.Context, policies *collector.PolicyCollection) error {
	configAnalyzer := analyzer.NewConfigAnalyzer(Client, policies)
	findings := configAnalyzer.Analyze(ctx, namespace)

	report := &output.Report{
		Title:     "Mesh Policy Audit",
		Timestamp: time.Now(),
	}
	for _, f := range findings {
		report.AddFinding(f)
	}

	formatter := output.New(outputFmt)
	formatter.PrintReport(report)
	return nil
}

func printAuthzPolicySuggestion(req *analyzer.TrafficRequest) {
	ns := req.DestNamespace
	if ns == "" {
		ns = "TARGET_NAMESPACE"
	}

	policy := fmt.Sprintf(`apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-%s-to-%s
  namespace: %s
spec:
  selector:
    matchLabels:
      app: %s  # <-- adjust to match destination pod labels
  action: ALLOW
  rules:
  - from:
    - source:
        principals:
        - "%s"
    to:
    - operation:
        ports:
        - "%d"
        paths:
        - "%s"
        methods:
        - "%s"`,
		sanitizeName(req.SourceServiceAccount),
		sanitizeName(req.DestService),
		ns,
		req.DestService,
		req.SourcePrincipal,
		req.DestPort,
		req.DestPath,
		req.Method,
	)
	fmt.Println()
	for _, line := range strings.Split(policy, "\n") {
		fmt.Printf("    %s\n", color.CyanString(line))
	}
	fmt.Println()
}

// Helpers

func parsePrincipal(principal string) (namespace, serviceAccount string) {
	// spiffe://cluster.local/ns/NAMESPACE/sa/SERVICE_ACCOUNT
	parts := strings.Split(principal, "/")
	for i, part := range parts {
		if part == "ns" && i+1 < len(parts) {
			namespace = parts[i+1]
		}
		if part == "sa" && i+1 < len(parts) {
			serviceAccount = parts[i+1]
		}
	}
	return namespace, serviceAccount
}

func severityCountStr(count int, severity string) string {
	if count == 0 {
		return color.GreenString("0")
	}
	switch severity {
	case "CRITICAL":
		return color.New(color.FgRed, color.Bold).Sprintf("%d", count)
	case "ERROR":
		return color.RedString("%d", count)
	case "WARN":
		return color.YellowString("%d", count)
	default:
		return fmt.Sprintf("%d", count)
	}
}

func findingSeverityIcon(severity string) string {
	switch severity {
	case "CRITICAL":
		return color.New(color.FgRed, color.Bold).Sprint("☠")
	case "ERROR":
		return color.RedString("✗")
	case "WARN":
		return color.YellowString("⚠")
	default:
		return color.CyanString("ℹ")
	}
}

func sanitizeName(name string) string {
	return strings.ReplaceAll(name, "_", "-")
}
