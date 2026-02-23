package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	istiov1beta1 "istio.io/api/security/v1beta1"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/istio-doctor/pkg/analyzer"
	"github.com/istio-doctor/pkg/collector"
	"github.com/istio-doctor/pkg/output"
)

var (
	simulateFile    string
	simulateVerbose bool
)

var simulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Simulate the impact of applying a new policy without applying it",
	Long: `Simulate what would happen if a new AuthorizationPolicy is applied.

Shows:
  - Which workloads are affected by the policy selector
  - Traffic flows that would be newly ALLOWED
  - Traffic flows that would be newly BLOCKED
  - Warnings about dangerous policy patterns

This is a dry-run analysis only - no changes are made to the cluster.`,
	Example: `  # Simulate applying a new AuthorizationPolicy
  istio-doctor simulate -f new-policy.yaml

  # Show unchanged flows too
  istio-doctor simulate -f new-policy.yaml --verbose-flows

  # Simulate from stdin
  cat policy.yaml | istio-doctor simulate -f -`,
	RunE: runSimulate,
}

func init() {
	simulateCmd.Flags().StringVarP(&simulateFile, "file", "f", "",
		"Path to AuthorizationPolicy YAML file (use '-' for stdin)")
	simulateCmd.Flags().BoolVar(&simulateVerbose, "verbose-flows", false,
		"Show unchanged traffic flows in addition to changed ones")
	simulateCmd.MarkFlagRequired("file")
}

func runSimulate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var rawData []byte
	var err error

	if simulateFile == "-" {
		rawData, err = io.ReadAll(os.Stdin)
	} else {
		rawData, err = os.ReadFile(simulateFile)
	}
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	policy, err := parseAuthzPolicy(rawData)
	if err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}

	fmt.Printf("\n  Simulating policy: %s/%s (Action: %s)\n\n",
		color.CyanString(policy.Namespace),
		color.CyanString(policy.Name),
		color.YellowString(policy.Spec.GetAction().String()))

	policyCollector := collector.NewPolicyCollector(Client)
	policies, err := policyCollector.Collect(ctx, namespace)
	if err != nil {
		return fmt.Errorf("collect policies: %w", err)
	}

	sim := analyzer.NewPolicySimulator(Client, policies)
	result, err := sim.SimulateAuthzPolicy(ctx, policy)
	if err != nil {
		return fmt.Errorf("simulation failed: %w", err)
	}

	printSimulationResult(result)
	return nil
}

func printSimulationResult(result *analyzer.SimulationResult) {
	printSectionHeader("SIMULATION SUMMARY")
	output.PrintKeyValue("  Policy",             fmt.Sprintf("%s/%s", result.PolicyNamespace, result.PolicyName))
	output.PrintKeyValue("  Action",             result.PolicyAction)
	output.PrintKeyValue("  Affected Workloads", fmt.Sprintf("%d pods match the policy selector", result.AffectedWorkloads))
	fmt.Println()

	if len(result.Warnings) > 0 {
		printSectionHeader("⚠ WARNINGS")
		for _, w := range result.Warnings {
			fmt.Printf("  %s\n", color.YellowString(w))
		}
		fmt.Println()
	}

	printSectionHeader("IMPACT")
	if result.BlockedCount == 0 && result.AllowedCount == 0 {
		output.PrintSuccess("No traffic flow changes - this policy has no effect on current traffic")
	} else {
		fmt.Printf("  %s  |  %s\n",
			color.GreenString("✓ Newly ALLOWED: %d flows", result.AllowedCount),
			color.RedString("✗ Newly BLOCKED: %d flows", result.BlockedCount))
	}
	fmt.Println()

	if len(result.NewlyBlocked) > 0 {
		printSectionHeader(fmt.Sprintf("NEWLY BLOCKED (%d flows)", len(result.NewlyBlocked)))
		for _, flow := range result.NewlyBlocked {
			fmt.Printf("  %s %s/%s → %s/%s:%d\n",
				color.RedString("-"),
				flow.Source.Namespace, flow.Source.ServiceAccount,
				flow.Destination.Namespace, flow.Destination.ServiceName, flow.Port)
			if flow.ChangeReason != "" {
				fmt.Printf("    %s\n", color.New(color.Faint).Sprint(flow.ChangeReason))
			}
		}
		fmt.Printf("\n  %s Review ALL blocked flows before applying!\n\n", color.RedString("⚠"))
	}

	if len(result.NewlyAllowed) > 0 {
		printSectionHeader(fmt.Sprintf("NEWLY ALLOWED (%d flows)", len(result.NewlyAllowed)))
		for _, flow := range result.NewlyAllowed {
			fmt.Printf("  %s %s/%s → %s/%s:%d\n",
				color.GreenString("+"),
				flow.Source.Namespace, flow.Source.ServiceAccount,
				flow.Destination.Namespace, flow.Destination.ServiceName, flow.Port)
		}
		fmt.Println()
	}

	if simulateVerbose && len(result.Unchanged) > 0 {
		printSectionHeader(fmt.Sprintf("UNCHANGED (%d flows)", len(result.Unchanged)))
		for _, flow := range result.Unchanged {
			fmt.Printf("  %s %s/%s → %s/%s:%d  [%s]\n",
				color.New(color.Faint).Sprint("="),
				flow.Source.Namespace, flow.Source.ServiceAccount,
				flow.Destination.Namespace, flow.Destination.ServiceName, flow.Port,
				flow.PreviousDecision)
		}
		fmt.Println()
	}

	printSectionHeader("RECOMMENDATION")
	if result.BlockedCount > 0 {
		fmt.Printf("  %s This policy blocks %d existing flows. Review before applying.\n",
			color.RedString("⚠"), result.BlockedCount)
	} else if len(result.Warnings) > 0 {
		fmt.Printf("  %s Warnings found - review carefully before applying.\n", color.YellowString("⚠"))
	} else {
		fmt.Printf("  %s No unexpected impact detected. Safe to apply.\n", color.GreenString("✓"))
	}
	fmt.Printf("  %s kubectl apply -f %s\n\n", color.CyanString("→"), simulateFile)
}

func parseAuthzPolicy(rawYAML []byte) (*securityv1beta1.AuthorizationPolicy, error) {
	jsonData, err := yaml.YAMLToJSON(rawYAML)
	if err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	var raw struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec istiov1beta1.AuthorizationPolicy `json:"spec"`
	}

	if err := json.Unmarshal(jsonData, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal policy: %w", err)
	}

	ns := raw.Metadata.Namespace
	if ns == "" {
		ns = "default"
	}
	if namespace != "" {
		ns = namespace
	}

	policy := &securityv1beta1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      raw.Metadata.Name,
			Namespace: ns,
		},
		Spec: raw.Spec,
	}

	return policy, nil
}
