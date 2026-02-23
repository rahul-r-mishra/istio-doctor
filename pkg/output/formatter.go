package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// Severity levels for findings.
type Severity string

const (
	SeverityPass    Severity = "PASS"
	SeverityInfo    Severity = "INFO"
	SeverityWarning Severity = "WARN"
	SeverityError   Severity = "ERROR"
	SeverityCritical Severity = "CRITICAL"
)

// Finding represents a single diagnostic finding.
type Finding struct {
	ID          string            `json:"id"`
	Severity    Severity          `json:"severity"`
	Category    string            `json:"category"`
	Resource    string            `json:"resource"`
	Namespace   string            `json:"namespace,omitempty"`
	Message     string            `json:"message"`
	Detail      string            `json:"detail,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// Report is a collection of findings with summary metadata.
type Report struct {
	Title     string    `json:"title"`
	Cluster   string    `json:"cluster,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Duration  string    `json:"duration,omitempty"`
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
}

// Summary holds aggregated counts.
type Summary struct {
	Total    int `json:"total"`
	Pass     int `json:"pass"`
	Info     int `json:"info"`
	Warnings int `json:"warnings"`
	Errors   int `json:"errors"`
	Critical int `json:"critical"`
}

func (r *Report) AddFinding(f Finding) {
	f.Timestamp = time.Now()
	r.Findings = append(r.Findings, f)
	r.Summary.Total++
	switch f.Severity {
	case SeverityPass:
		r.Summary.Pass++
	case SeverityInfo:
		r.Summary.Info++
	case SeverityWarning:
		r.Summary.Warnings++
	case SeverityError:
		r.Summary.Errors++
	case SeverityCritical:
		r.Summary.Critical++
	}
}

// Formatter handles output rendering.
type Formatter struct {
	Format string
	Writer io.Writer
}

func New(format string) *Formatter {
	return &Formatter{Format: format, Writer: os.Stdout}
}

func (f *Formatter) PrintReport(r *Report) {
	switch f.Format {
	case "json":
		f.printJSON(r)
	case "yaml":
		f.printYAML(r)
	case "prometheus":
		f.printPrometheus(r)
	default:
		f.printTable(r)
	}
}

func (f *Formatter) printJSON(r *Report) {
	enc := json.NewEncoder(f.Writer)
	enc.SetIndent("", "  ")
	enc.Encode(r)
}

func (f *Formatter) printYAML(r *Report) {
	// Simple YAML output via JSON marshal for now
	data, _ := json.MarshalIndent(r, "", "  ")
	fmt.Fprintln(f.Writer, string(data))
}

func (f *Formatter) printPrometheus(r *Report) {
	ts := r.Timestamp.UnixMilli()
	fmt.Fprintf(f.Writer, "# HELP istio_doctor_findings_total Total findings by severity\n")
	fmt.Fprintf(f.Writer, "# TYPE istio_doctor_findings_total gauge\n")
	fmt.Fprintf(f.Writer, `istio_doctor_findings_total{severity="pass"} %d %d`+"\n", r.Summary.Pass, ts)
	fmt.Fprintf(f.Writer, `istio_doctor_findings_total{severity="info"} %d %d`+"\n", r.Summary.Info, ts)
	fmt.Fprintf(f.Writer, `istio_doctor_findings_total{severity="warn"} %d %d`+"\n", r.Summary.Warnings, ts)
	fmt.Fprintf(f.Writer, `istio_doctor_findings_total{severity="error"} %d %d`+"\n", r.Summary.Errors, ts)
	fmt.Fprintf(f.Writer, `istio_doctor_findings_total{severity="critical"} %d %d`+"\n", r.Summary.Critical, ts)
	for _, finding := range r.Findings {
		if finding.Severity != SeverityPass {
			ns := finding.Namespace
			if ns == "" {
				ns = "cluster"
			}
			safe := strings.ReplaceAll(finding.Resource, `"`, `\"`)
			fmt.Fprintf(f.Writer, `istio_doctor_finding{id=%q,severity=%q,category=%q,namespace=%q,resource=%q} 1 %d`+"\n",
				finding.ID, string(finding.Severity), finding.Category, ns, safe, ts)
		}
	}
}

func (f *Formatter) printTable(r *Report) {
	w := f.Writer

	// Header
	fmt.Fprintln(w, "")
	printTitle(w, r.Title)
	if r.Duration != "" {
		fmt.Fprintf(w, "  Scanned in %s  |  %s\n\n", r.Duration, r.Timestamp.Format("2006-01-02 15:04:05"))
	}

	// Summary bar
	printSummaryBar(w, r.Summary)
	fmt.Fprintln(w, "")

	if len(r.Findings) == 0 {
		color.Green("  ✓ No issues found.\n")
		return
	}

	// Group findings by category
	categories := make(map[string][]Finding)
	catOrder := []string{}
	for _, f := range r.Findings {
		if _, ok := categories[f.Category]; !ok {
			catOrder = append(catOrder, f.Category)
		}
		categories[f.Category] = append(categories[f.Category], f)
	}

	for _, cat := range catOrder {
		findings := categories[cat]
		fmt.Fprintf(w, "  %s\n", color.New(color.Bold, color.FgWhite).Sprintf("━━ %s ━━", strings.ToUpper(cat)))

		table := tablewriter.NewWriter(w)
		table.SetHeader([]string{"Severity", "Resource", "Namespace", "Message"})
		table.SetBorder(false)
		table.SetColumnSeparator("  ")
		table.SetHeaderLine(false)
		table.SetTablePadding("  ")
		table.SetNoWhiteSpace(true)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetColWidth(60)

		for _, finding := range findings {
			sev := severityColored(finding.Severity)
			ns := finding.Namespace
			if ns == "" {
				ns = "-"
			}
			msg := finding.Message
			if len(msg) > 80 {
				msg = msg[:77] + "..."
			}
			table.Append([]string{sev, finding.Resource, ns, msg})
		}
		table.Render()

		// Print detail + remediation for non-pass findings
		for _, finding := range findings {
			if finding.Severity != SeverityPass && (finding.Detail != "" || finding.Remediation != "") {
				fmt.Fprintf(w, "\n    %s %s\n", severityIcon(finding.Severity), color.New(color.Bold).Sprint(finding.Resource))
				if finding.Detail != "" {
					fmt.Fprintf(w, "      Detail:      %s\n", finding.Detail)
				}
				if finding.Remediation != "" {
					fmt.Fprintf(w, "      Remediation: %s\n", color.CyanString(finding.Remediation))
				}
			}
		}
		fmt.Fprintln(w, "")
	}
}

func printTitle(w io.Writer, title string) {
	line := strings.Repeat("─", len(title)+4)
	fmt.Fprintf(w, "  %s\n  │ %s │\n  %s\n", line, color.New(color.Bold, color.FgCyan).Sprint(title), line)
}

func printSummaryBar(w io.Writer, s Summary) {
	pass := color.GreenString("✓ PASS: %d", s.Pass)
	info := color.CyanString("ℹ INFO: %d", s.Info)
	warn := color.YellowString("⚠ WARN: %d", s.Warnings)
	errs := color.RedString("✗ ERROR: %d", s.Errors)
	crit := color.New(color.FgRed, color.Bold).Sprintf("☠ CRITICAL: %d", s.Critical)
	fmt.Fprintf(w, "  %s  %s  %s  %s  %s  (Total: %d)\n", pass, info, warn, errs, crit, s.Total)
}

func severityColored(s Severity) string {
	switch s {
	case SeverityPass:
		return color.GreenString("✓ PASS")
	case SeverityInfo:
		return color.CyanString("ℹ INFO")
	case SeverityWarning:
		return color.YellowString("⚠ WARN")
	case SeverityError:
		return color.RedString("✗ ERROR")
	case SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint("☠ CRITICAL")
	default:
		return string(s)
	}
}

func severityIcon(s Severity) string {
	switch s {
	case SeverityPass:
		return color.GreenString("✓")
	case SeverityInfo:
		return color.CyanString("ℹ")
	case SeverityWarning:
		return color.YellowString("⚠")
	case SeverityError:
		return color.RedString("✗")
	case SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint("☠")
	default:
		return "?"
	}
}

// PrintSection prints a bold section header.
func PrintSection(title string) {
	fmt.Printf("\n  %s\n", color.New(color.Bold, color.FgCyan).Sprint("▶ "+title))
}

// PrintKeyValue prints a key-value line.
func PrintKeyValue(key, value string) {
	fmt.Printf("  %-30s %s\n", color.New(color.Bold).Sprint(key+":"), value)
}

// PrintSuccess prints a success message.
func PrintSuccess(msg string) {
	fmt.Printf("  %s %s\n", color.GreenString("✓"), msg)
}

// PrintWarning prints a warning message.
func PrintWarning(msg string) {
	fmt.Printf("  %s %s\n", color.YellowString("⚠"), msg)
}

// PrintError prints an error message.
func PrintError(msg string) {
	fmt.Printf("  %s %s\n", color.RedString("✗"), msg)
}

// PrintInfo prints an info message.
func PrintInfo(msg string) {
	fmt.Printf("  %s %s\n", color.CyanString("ℹ"), msg)
}
