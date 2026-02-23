package analyzer

import (
	"fmt"
	"strings"

	istiov1beta1 "istio.io/api/security/v1beta1"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
)

// TrafficRequest represents a traffic request to evaluate against policies.
type TrafficRequest struct {
	// Source
	SourceNamespace      string
	SourceServiceAccount string
	SourcePrincipal      string // Full SPIFFE URI or derived from NS+SA
	SourceIP             string

	// Destination
	DestNamespace string
	DestService   string
	DestPort      uint32
	DestPath      string
	Method        string

	// Protocol
	Protocol string // HTTP, GRPC, TCP
}

// DeriveSourcePrincipal builds the SPIFFE URI for a source.
func DeriveSourcePrincipal(trustDomain, namespace, serviceAccount string) string {
	if serviceAccount == "" {
		serviceAccount = "default"
	}
	return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, namespace, serviceAccount)
}

// AuthzDecision is the result of policy evaluation.
type AuthzDecision struct {
	Allowed        bool
	Reason         string
	MatchedPolicy  string
	MatchedRule    int
	DenyPolicies   []PolicyMatch
	AllowPolicies  []PolicyMatch
	Warnings       []string
}

// PolicyMatch records which policy/rule matched.
type PolicyMatch struct {
	PolicyName      string
	PolicyNamespace string
	RuleIndex       int
	MatchReason     string
	Action          string // ALLOW or DENY
}

// AuthzAnalyzer evaluates Istio AuthorizationPolicy against traffic requests.
type AuthzAnalyzer struct {
	TrustDomain string
}

func NewAuthzAnalyzer(trustDomain string) *AuthzAnalyzer {
	if trustDomain == "" {
		trustDomain = "cluster.local"
	}
	return &AuthzAnalyzer{TrustDomain: trustDomain}
}

// Evaluate runs the full Istio authz evaluation logic:
// 1. If any DENY policy matches → DENY
// 2. If no ALLOW policy exists → ALLOW (implicit allow)
// 3. If ALLOW policies exist but none match → DENY
// 4. If an ALLOW policy matches → ALLOW
func (a *AuthzAnalyzer) Evaluate(req *TrafficRequest, policies []securityv1beta1.AuthorizationPolicy) *AuthzDecision {
	decision := &AuthzDecision{}

	// Filter policies that apply to the destination workload
	applicable := a.filterApplicablePolicies(req, policies)

	var denyPolicies []securityv1beta1.AuthorizationPolicy
	var allowPolicies []securityv1beta1.AuthorizationPolicy
	var auditPolicies []securityv1beta1.AuthorizationPolicy

	for _, p := range applicable {
		action := p.Spec.GetAction()
		switch action {
		case istiov1beta1.AuthorizationPolicy_DENY:
			denyPolicies = append(denyPolicies, p)
		case istiov1beta1.AuthorizationPolicy_AUDIT:
			auditPolicies = append(auditPolicies, p)
		default: // ALLOW or unset (defaults to ALLOW)
			allowPolicies = append(allowPolicies, p)
		}
	}
	_ = auditPolicies

	// Phase 1: Check DENY policies
	for _, p := range denyPolicies {
		matches, ruleIdx, reason := a.matchesRules(req, p.Spec.GetRules())
		if matches {
			match := PolicyMatch{
				PolicyName:      p.Name,
				PolicyNamespace: p.Namespace,
				RuleIndex:       ruleIdx,
				MatchReason:     reason,
				Action:          "DENY",
			}
			decision.DenyPolicies = append(decision.DenyPolicies, match)
			decision.Allowed = false
			decision.Reason = fmt.Sprintf("DENY policy '%s/%s' rule[%d] matched: %s",
				p.Namespace, p.Name, ruleIdx, reason)
			decision.MatchedPolicy = fmt.Sprintf("%s/%s", p.Namespace, p.Name)
			decision.MatchedRule = ruleIdx
			return decision
		}
		// Check for common misconfigurations
		a.checkPolicyMisconfigurations(&p, decision)
	}

	// Phase 2: If no ALLOW policies, implicitly allow
	if len(allowPolicies) == 0 {
		decision.Allowed = true
		decision.Reason = "No ALLOW policies found for destination workload - implicit allow"
		if len(denyPolicies) > 0 {
			decision.Reason = "DENY policies checked (no match), no ALLOW policies - implicit allow"
		}
		return decision
	}

	// Phase 3: Check ALLOW policies
	for _, p := range allowPolicies {
		// Empty rules = deny all (common footgun!)
		if len(p.Spec.GetRules()) == 0 {
			decision.AllowPolicies = append(decision.AllowPolicies, PolicyMatch{
				PolicyName:      p.Name,
				PolicyNamespace: p.Namespace,
				Action:          "ALLOW",
				MatchReason:     "Empty rules - denies all traffic",
			})
			decision.Warnings = append(decision.Warnings,
				fmt.Sprintf("⚠ Policy '%s/%s' has ALLOW action with empty rules[] - this DENIES all traffic to the workload (common footgun!)",
					p.Namespace, p.Name))
			continue
		}

		matches, ruleIdx, reason := a.matchesRules(req, p.Spec.GetRules())
		if matches {
			match := PolicyMatch{
				PolicyName:      p.Name,
				PolicyNamespace: p.Namespace,
				RuleIndex:       ruleIdx,
				MatchReason:     reason,
				Action:          "ALLOW",
			}
			decision.AllowPolicies = append(decision.AllowPolicies, match)
			decision.Allowed = true
			decision.Reason = fmt.Sprintf("ALLOW policy '%s/%s' rule[%d] matched: %s",
				p.Namespace, p.Name, ruleIdx, reason)
			decision.MatchedPolicy = fmt.Sprintf("%s/%s", p.Namespace, p.Name)
			decision.MatchedRule = ruleIdx
			return decision
		}

		// Record near-misses for diagnostics
		a.checkPolicyMisconfigurations(&p, decision)
	}

	// No ALLOW policy matched
	decision.Allowed = false
	decision.Reason = fmt.Sprintf("ALLOW policies exist (%d) but none matched the request", len(allowPolicies))

	// Provide helpful near-miss analysis
	a.analyzeAllowPolicyMismatches(req, allowPolicies, decision)

	return decision
}

// filterApplicablePolicies returns policies that select the destination workload.
func (a *AuthzAnalyzer) filterApplicablePolicies(req *TrafficRequest, policies []securityv1beta1.AuthorizationPolicy) []securityv1beta1.AuthorizationPolicy {
	var result []securityv1beta1.AuthorizationPolicy
	for _, p := range policies {
		// Policy must be in dest namespace or istio-system (root namespace)
		if p.Namespace != req.DestNamespace && p.Namespace != "istio-system" {
			continue
		}

		// No selector = applies to all workloads in namespace
		selector := p.Spec.GetSelector()
		if selector == nil || len(selector.MatchLabels) == 0 {
			result = append(result, p)
			continue
		}

		// TODO: in real impl, we'd check if selector matches dest pod labels
		// For now we include based on namespace match
		result = append(result, p)
	}
	return result
}

// matchesRules checks if a request matches any of the rules in a policy.
// Returns: matched bool, rule index, reason string.
func (a *AuthzAnalyzer) matchesRules(req *TrafficRequest, rules []*istiov1beta1.Rule) (bool, int, string) {
	for i, rule := range rules {
		fromMatched, fromReason := a.matchesFrom(req, rule.From)
		if !fromMatched {
			continue
		}
		toMatched, toReason := a.matchesTo(req, rule.To)
		if !toMatched {
			continue
		}
		condMatched, condReason := a.matchesConditions(req, rule.When)
		if !condMatched {
			continue
		}
		reason := strings.Join(filterEmpty([]string{fromReason, toReason, condReason}), "; ")
		return true, i, reason
	}
	return false, -1, ""
}

func (a *AuthzAnalyzer) matchesFrom(req *TrafficRequest, froms []*istiov1beta1.Rule_From) (bool, string) {
	if len(froms) == 0 {
		return true, "no source constraints"
	}
	for _, from := range froms {
		if from.Source == nil {
			return true, "empty source"
		}
		src := from.Source

		// Check principals
		if len(src.Principals) > 0 {
			matched := false
			for _, p := range src.Principals {
				if matchesPattern(p, req.SourcePrincipal) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			return true, fmt.Sprintf("principal '%s' matched", req.SourcePrincipal)
		}

		// Check namespaces
		if len(src.Namespaces) > 0 {
			for _, ns := range src.Namespaces {
				if matchesPattern(ns, req.SourceNamespace) {
					return true, fmt.Sprintf("namespace '%s' matched", req.SourceNamespace)
				}
			}
			continue
		}

		// Check IP blocks
		if len(src.IpBlocks) > 0 {
			for _, ipBlock := range src.IpBlocks {
				if matchesPattern(ipBlock, req.SourceIP) {
					return true, fmt.Sprintf("IP block '%s' matched", req.SourceIP)
				}
			}
			continue
		}

		// No constraints in this source
		return true, "no source constraints"
	}
	return false, ""
}

func (a *AuthzAnalyzer) matchesTo(req *TrafficRequest, tos []*istiov1beta1.Rule_To) (bool, string) {
	if len(tos) == 0 {
		return true, "no operation constraints"
	}
	for _, to := range tos {
		if to.Operation == nil {
			return true, "empty operation"
		}
		op := to.Operation

		portMatched := true
		if len(op.Ports) > 0 {
			portMatched = false
			for _, p := range op.Ports {
				if p == fmt.Sprintf("%d", req.DestPort) {
					portMatched = true
					break
				}
			}
		}

		pathMatched := true
		if len(op.Paths) > 0 {
			pathMatched = false
			for _, p := range op.Paths {
				if matchesPattern(p, req.DestPath) {
					pathMatched = true
					break
				}
			}
		}

		methodMatched := true
		if len(op.Methods) > 0 {
			methodMatched = false
			for _, m := range op.Methods {
				if m == "*" || strings.EqualFold(m, req.Method) {
					methodMatched = true
					break
				}
			}
		}

		hostMatched := true
		if len(op.Hosts) > 0 {
			hostMatched = false
			for _, h := range op.Hosts {
				if matchesPattern(h, req.DestService) {
					hostMatched = true
					break
				}
			}
		}

		if portMatched && pathMatched && methodMatched && hostMatched {
			return true, fmt.Sprintf("port=%d path=%s method=%s", req.DestPort, req.DestPath, req.Method)
		}
	}
	return false, ""
}

func (a *AuthzAnalyzer) matchesConditions(req *TrafficRequest, conditions []*istiov1beta1.Condition) (bool, string) {
	if len(conditions) == 0 {
		return true, ""
	}
	// For now, all conditions assumed matched (custom headers etc. require runtime context)
	return true, fmt.Sprintf("%d conditions (not evaluated at analysis time)", len(conditions))
}

// checkPolicyMisconfigurations detects common authz policy mistakes.
func (a *AuthzAnalyzer) checkPolicyMisconfigurations(p *securityv1beta1.AuthorizationPolicy, decision *AuthzDecision) {
	// 1. ALLOW policy with empty rules
	if p.Spec.GetAction() == istiov1beta1.AuthorizationPolicy_ALLOW && len(p.Spec.GetRules()) == 0 {
		decision.Warnings = append(decision.Warnings,
			fmt.Sprintf("CRITICAL: '%s/%s' is an ALLOW policy with empty rules - blocks ALL traffic", p.Namespace, p.Name))
	}

	// 2. Check for likely typos in principal patterns
	for _, rule := range p.Spec.GetRules() {
		for _, from := range rule.GetFrom() {
			for _, principal := range from.GetSource().GetPrincipals() {
				if !strings.HasPrefix(principal, "spiffe://") && !strings.Contains(principal, "*") {
					decision.Warnings = append(decision.Warnings,
						fmt.Sprintf("Policy '%s/%s': principal '%s' doesn't start with 'spiffe://' - may never match",
							p.Namespace, p.Name, principal))
				}
			}
		}
	}

	// 3. Empty namespace in principal (common mistake)
	for _, rule := range p.Spec.GetRules() {
		for _, from := range rule.GetFrom() {
			for _, ns := range from.GetSource().GetNamespaces() {
				if ns == "" {
					decision.Warnings = append(decision.Warnings,
						fmt.Sprintf("Policy '%s/%s': empty namespace in source.namespaces - this will match all namespaces unexpectedly",
							p.Namespace, p.Name))
				}
			}
		}
	}
}

// analyzeAllowPolicyMismatches provides near-miss analysis for ALLOW policy failures.
func (a *AuthzAnalyzer) analyzeAllowPolicyMismatches(req *TrafficRequest, policies []securityv1beta1.AuthorizationPolicy, decision *AuthzDecision) {
	for _, p := range policies {
		for i, rule := range p.Spec.GetRules() {
			fromMatched, _ := a.matchesFrom(req, rule.From)
			toMatched, _ := a.matchesTo(req, rule.To)

			if fromMatched && !toMatched {
				// Source matched but destination didn't - helpful hint
				decision.Warnings = append(decision.Warnings,
					fmt.Sprintf("Policy '%s/%s' rule[%d]: source principal/namespace matched but operation (port/path/method) did not match - check ports/paths",
						p.Namespace, p.Name, i))
			} else if !fromMatched && toMatched {
				// Destination matched but source didn't - helpful hint
				decision.Warnings = append(decision.Warnings,
					fmt.Sprintf("Policy '%s/%s' rule[%d]: operation (port/path) matched but source principal did not - expected principal: '%s'",
						p.Namespace, p.Name, i, req.SourcePrincipal))
			}
		}
	}
}

// AuthzAuditResult holds the full audit result for a namespace or cluster.
type AuthzAuditResult struct {
	Namespace  string
	Findings   []AuthzFinding
	Statistics AuthzStatistics
}

// AuthzFinding is a single authz audit finding.
type AuthzFinding struct {
	Severity    string
	PolicyName  string
	Namespace   string
	Description string
	Remediation string
}

// AuthzStatistics holds authz audit stats.
type AuthzStatistics struct {
	TotalPolicies     int
	AllowPolicies     int
	DenyPolicies      int
	EmptyRulePolicies int
	MissingSelectors  int
	PotentialTypos    int
}

// AuditPolicies performs a static audit of all authorization policies.
func (a *AuthzAnalyzer) AuditPolicies(policies []securityv1beta1.AuthorizationPolicy) *AuthzAuditResult {
	result := &AuthzAuditResult{}
	result.Statistics.TotalPolicies = len(policies)

	for _, p := range policies {
		action := p.Spec.GetAction()
		switch action {
		case istiov1beta1.AuthorizationPolicy_DENY:
			result.Statistics.DenyPolicies++
		default:
			result.Statistics.AllowPolicies++
		}

		// 1. ALLOW with empty rules (denies all traffic)
		if action == istiov1beta1.AuthorizationPolicy_ALLOW && len(p.Spec.GetRules()) == 0 {
			result.Statistics.EmptyRulePolicies++
			result.Findings = append(result.Findings, AuthzFinding{
				Severity:    "CRITICAL",
				PolicyName:  p.Name,
				Namespace:   p.Namespace,
				Description: "ALLOW policy with empty rules[] effectively DENIES all traffic to selected workloads",
				Remediation: fmt.Sprintf("kubectl patch authorizationpolicy %s -n %s --type=json -p '[{\"op\":\"add\",\"path\":\"/spec/rules\",\"value\":[{}]}]'", p.Name, p.Namespace),
			})
		}

		// 2. Policy with no workload selector (applies to entire namespace)
		if p.Spec.GetSelector() == nil || len(p.Spec.GetSelector().MatchLabels) == 0 {
			result.Statistics.MissingSelectors++
			result.Findings = append(result.Findings, AuthzFinding{
				Severity:    "WARN",
				PolicyName:  p.Name,
				Namespace:   p.Namespace,
				Description: "Policy has no workload selector - applies to ALL workloads in namespace. Intentional?",
				Remediation: fmt.Sprintf("Add spec.selector.matchLabels to '%s' if you intended to target specific workloads", p.Name),
			})
		}

		// 3. Check for principal format issues
		for ri, rule := range p.Spec.GetRules() {
			for _, from := range rule.GetFrom() {
				for _, principal := range from.GetSource().GetPrincipals() {
					if principal != "*" && !strings.HasPrefix(principal, "spiffe://") && !strings.HasPrefix(principal, "cluster.local/") {
						result.Statistics.PotentialTypos++
						result.Findings = append(result.Findings, AuthzFinding{
							Severity:    "ERROR",
							PolicyName:  p.Name,
							Namespace:   p.Namespace,
							Description: fmt.Sprintf("Rule[%d]: principal '%s' is not a valid SPIFFE URI or wildcard - will never match", ri, principal),
							Remediation: fmt.Sprintf("Use format: 'spiffe://cluster.local/ns/<namespace>/sa/<service-account>' or 'cluster.local/ns/<namespace>/sa/<service-account>'"),
						})
					}
				}

				// 4. NOT_PRINCIPALS that use full deny could be a mistake
				for _, notPrincipal := range from.GetSource().GetNotPrincipals() {
					if notPrincipal == "*" {
						result.Findings = append(result.Findings, AuthzFinding{
							Severity:    "WARN",
							PolicyName:  p.Name,
							Namespace:   p.Namespace,
							Description: fmt.Sprintf("Rule[%d]: notPrincipals='*' - this denies all authenticated principals", ri),
							Remediation: "Verify this is intentional; this blocks all mTLS traffic",
						})
					}
				}
			}

			// 5. Check for overly broad DENY on empty To (blocks all ports/paths)
			if action == istiov1beta1.AuthorizationPolicy_DENY && len(rule.GetTo()) == 0 && len(rule.GetFrom()) > 0 {
				result.Findings = append(result.Findings, AuthzFinding{
					Severity:    "WARN",
					PolicyName:  p.Name,
					Namespace:   p.Namespace,
					Description: fmt.Sprintf("Rule[%d]: DENY policy with no 'to' constraints blocks ALL ports/paths from specified sources", ri),
					Remediation: "Add spec.rules[].to[] with port/path constraints if you want targeted denial",
				})
			}
		}
	}

	return result
}

// matchesPattern checks if a value matches a pattern (supports * prefix/suffix wildcards).
func matchesPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == value {
		return true
	}
	// Prefix wildcard: *.example.com
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(value, suffix)
	}
	// Suffix wildcard: spiffe://cluster.local/*
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(value, prefix)
	}
	return false
}

func filterEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
