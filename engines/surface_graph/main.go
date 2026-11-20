// surface_graph - High-Performance Web Application Attack Surface & Topology Engine
//
// Analyzes harvested routes, directory hierarchies, and asset artifacts to build
// an endpoint topology graph, fingerprint technology stacks, identify sensitive routes,
// and compute overall attack surface risk metrics.
//
// Zero external dependencies. Concurrently analyzes targets via goroutines.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type SurfaceResult struct {
	TotalRoutes     int          `json:"total_routes"`
	Nodes           []string     `json:"nodes"`
	Edges           []Edge       `json:"edges"`
	Technologies    []TechFinger `json:"technologies"`
	SensitiveRoutes []string     `json:"sensitive_routes"`
	ExternalDomains []string     `json:"external_domains"`
	RiskScore       int          `json:"risk_score"`
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type TechFinger struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Evidence string `json:"evidence"`
}

// FlexibleHeaders supports unmarshaling JSON headers formatted as either
// map[string][]string, map[string]string, or map[string]interface{}.
type FlexibleHeaders map[string][]string

func (h *FlexibleHeaders) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	res := make(map[string][]string)
	for k, v := range raw {
		switch val := v.(type) {
		case string:
			res[k] = []string{val}
		case []interface{}:
			var strSlice []string
			for _, item := range val {
				if s, ok := item.(string); ok {
					strSlice = append(strSlice, s)
				}
			}
			res[k] = strSlice
		case []string:
			res[k] = val
		}
	}
	*h = res
	return nil
}

type FindingPayload struct {
	Severity      string   `json:"severity"`
	Category      string   `json:"category"`
	Title         string   `json:"title"`
	VendorContext string   `json:"vendor_context,omitempty"`
	Tags          []string `json:"tags,omitempty"`
}

type ScanPayload struct {
	Endpoints []string         `json:"endpoints"`
	Headers   FlexibleHeaders  `json:"headers"`
	Content   string           `json:"content"`
	Findings  []FindingPayload `json:"findings,omitempty"`
}

type InputPayload = ScanPayload

var vendorDomainKeywords = []string{
	"akamai", "tiqcdn", "tealium", "adobe", "demdex", "omtrdc",
	"google-analytics", "googletagmanager", "hotjar", "segment",
}

func isVendorRoute(ep string) bool {
	epLower := strings.ToLower(ep)
	for _, kw := range vendorDomainKeywords {
		if strings.Contains(epLower, kw) {
			return true
		}
	}
	return false
}

var editorialOrStaticIgnoredDirs = []string{
	"/news/", "/media/", "/blog/", "/press/", "/articles/",
	"/events/", "/stories/", "/publications/",
}

var ignoredStaticSuffixes = []string{
	".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg",
	".css", ".ico", ".woff", ".woff2",
}

var sensitiveStructuralMarkers = []string{
	"api-docs", "/.git", "/.env", "/graphql", "/swagger", "/openapi", "/actuator",
}

var sensitiveRouteTokens = map[string]bool{
	"admin": true, "login": true, "signin": true, "auth": true, "oauth": true,
	"token": true, "secret": true, "config": true, "actuator": true, "metrics": true,
	"upload": true, "debug": true, "internal": true, "graphql": true, "swagger": true,
	"openapi": true, "backup": true, "dump": true,
}

func isSensitiveRoute(pathOnly string) bool {
	if isVendorRoute(pathOnly) {
		return false
	}
	pathLower := strings.ToLower(pathOnly)
	for _, ignored := range editorialOrStaticIgnoredDirs {
		if strings.Contains(pathLower, ignored) {
			return false
		}
	}
	for _, suf := range ignoredStaticSuffixes {
		if strings.HasSuffix(pathLower, suf) {
			return false
		}
	}
	for _, marker := range sensitiveStructuralMarkers {
		if strings.Contains(pathLower, marker) {
			return true
		}
	}
	tokens := strings.FieldsFunc(pathLower, func(r rune) bool {
		return r == '/' || r == '-' || r == '_' || r == '.'
	})
	for _, tok := range tokens {
		if sensitiveRouteTokens[tok] {
			return true
		}
	}
	return false
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: surface_graph <json_path | dir <directory>>")
		os.Exit(1)
	}

	mode := os.Args[1]
	var payload InputPayload

	if mode == "dir" {
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: surface_graph dir <directory>")
			os.Exit(1)
		}
		dirPath := os.Args[2]
		payload = readFromDirectory(dirPath)
	} else {
		// Read from JSON file
		data, err := os.ReadFile(mode)
		if err != nil {
			// Fallback: try parsing argument directly as JSON string
			if errJson := json.Unmarshal([]byte(mode), &payload); errJson != nil {
				fmt.Fprintf(os.Stderr, "Failed to read input JSON: %v\n", err)
				os.Exit(1)
			}
		} else {
			if err := json.Unmarshal(data, &payload); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to unmarshal JSON file: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Debug print immediately after unmarshaling
	fmt.Fprintf(os.Stderr, "DEBUG: len(payload.Headers)=%d, len(payload.Content)=%d\n", len(payload.Headers), len(payload.Content))

	result := analyzeSurface(payload)
	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal output: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(out))
}

func readFromDirectory(dirPath string) InputPayload {
	var payload InputPayload
	payload.Headers = make(FlexibleHeaders)
	var endpoints []string
	var allContent strings.Builder

	reEndpoint := regexp.MustCompile(`['"]((?:/|https?://)[a-zA-Z0-9_?&=/\-\.:%]+)['"]`)
	cleanRoot, errRoot := filepath.Abs(filepath.Clean(dirPath))
	if errRoot != nil {
		return payload
	}
	if realRoot, errEval := filepath.EvalSymlinks(cleanRoot); errEval == nil {
		cleanRoot = realRoot
	}

	_ = filepath.Walk(cleanRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		realPath, errEval := filepath.EvalSymlinks(path)
		if errEval != nil {
			return nil
		}
		if !strings.HasPrefix(realPath, cleanRoot+string(os.PathSeparator)) && realPath != cleanRoot {
			return nil
		}
		data, err := os.ReadFile(realPath)
		if err != nil {
			return nil
		}
		contentStr := string(data)
		allContent.WriteString(contentStr)
		allContent.WriteString("\n")

		matches := reEndpoint.FindAllStringSubmatch(contentStr, -1)
		for _, m := range matches {
			if len(m) > 1 {
				endpoints = append(endpoints, m[1])
			}
		}
		return nil
	})

	payload.Endpoints = endpoints
	payload.Content = allContent.String()
	return payload
}

func isValidRoute(path string) bool {
	if len(path) == 0 || len(path) > 256 {
		return false
	}
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") && !strings.HasPrefix(path, "ws://") && !strings.HasPrefix(path, "wss://") {
		return false
	}

	invalidTokens := []string{
		"&&", "||", "return", "function", "var ", "let ", "const ",
		"test(", "match(", "replace(", "typeof ", "undefined", "null",
		";", "{", "}", "[", "]", "(", ")", "=>", "<", ">", "$", "\\",
		",", " ", "\t", "\n", "\r", "\"", "'", "`",
	}
	for _, tok := range invalidTokens {
		if strings.Contains(path, tok) {
			return false
		}
	}

	if strings.Contains(path, "d{") || strings.Contains(path, "w{") || strings.HasSuffix(path, "/i") || strings.HasSuffix(path, "/g") {
		return false
	}

	return true
}

func analyzeSurface(payload InputPayload) SurfaceResult {
	// Debug logging to verify IPC data reception
	fmt.Fprintf(os.Stderr, "DEBUG: Received %d endpoints, %d headers, %d content bytes\n",
		len(payload.Endpoints), len(payload.Headers), len(payload.Content))

	// Log header keys for debugging
	if len(payload.Headers) > 0 {
		headerKeys := make([]string, 0, len(payload.Headers))
		for k := range payload.Headers {
			headerKeys = append(headerKeys, k)
		}
		fmt.Fprintf(os.Stderr, "DEBUG: Header keys: %v\n", headerKeys)
	}

	nodeSet := make(map[string]bool)
	edgeSet := make(map[string]bool)
	var edges []Edge
	var sensitiveRoutes []string
	extDomainSet := make(map[string]bool)

	// Clean & Deduplicate endpoints
	for _, rawEp := range payload.Endpoints {
		ep := strings.TrimSpace(rawEp)
		if ep == "" || len(ep) < 2 || !isValidRoute(ep) {
			continue
		}

		// Check external domains
		if strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://") {
			parts := strings.Split(ep, "/")
			if len(parts) >= 3 {
				extDomainSet[parts[2]] = true
			}
		}

		// Normalize route path
		pathOnly := ep
		if idx := strings.Index(ep, "?"); idx != -1 {
			pathOnly = ep[:idx]
		}
		if idx := strings.Index(pathOnly, "#"); idx != -1 {
			pathOnly = pathOnly[:idx]
		}

		if !strings.HasPrefix(pathOnly, "/") {
			if idx := strings.Index(pathOnly, "://"); idx != -1 {
				rest := pathOnly[idx+3:]
				if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
					pathOnly = rest[slashIdx:]
				} else {
					pathOnly = "/"
				}
			} else {
				pathOnly = "/" + pathOnly
			}
		}

		if !isValidRoute(pathOnly) {
			continue
		}

		nodeSet[pathOnly] = true

		// Check sensitive route (excluding vendor, editorial/news/media, and static paths)
		if isSensitiveRoute(pathOnly) {
			sensitiveRoutes = append(sensitiveRoutes, pathOnly)
		}

		// Build topology edges (hierarchy)
		segments := strings.Split(strings.Trim(pathOnly, "/"), "/")
		curr := ""
		for _, seg := range segments {
			if seg == "" {
				continue
			}
			prev := curr
			if prev == "" {
				prev = "/"
			}
			curr = curr + "/" + seg
			nodeSet[curr] = true

			edgeKey := prev + " -> " + curr
			if !edgeSet[edgeKey] && prev != curr {
				edgeSet[edgeKey] = true
				edges = append(edges, Edge{From: prev, To: curr})
			}
		}
	}

	// Tech Stack Fingerprinting
	techs := fingerprintTechnologies(payload.Headers, payload.Content)

	// Normalized Risk Score Calculation (0 - 100)
	// Base baseline risk: 10
	riskScore := 10

	// 1. First-party sensitive routes (bounded at +15)
	dedupSensitive := deduplicate(sensitiveRoutes)
	if len(dedupSensitive) > 0 {
		routeScore := len(dedupSensitive) * 3
		if routeScore > 15 {
			routeScore = 15
		}
		riskScore += routeScore
	}

	// 2. Attack surface complexity (bounded at +10)
	if len(payload.Endpoints) > 30 {
		riskScore += 10
	} else if len(payload.Endpoints) > 10 {
		riskScore += 5
	}

	// 3. Category-capped & diminishing-returns Risk Score Calculation (0 - 100)
	riskScore = calculateRiskScore(riskScore, len(dedupSensitive), payload.Findings)

	nodes := make([]string, 0, len(nodeSet))
	for n := range nodeSet {
		nodes = append(nodes, n)
	}

	externalDomains := make([]string, 0, len(extDomainSet))
	for d := range extDomainSet {
		externalDomains = append(externalDomains, d)
	}

	if edges == nil {
		edges = make([]Edge, 0)
	}
	if techs == nil {
		techs = make([]TechFinger, 0)
	}
	if dedupSensitive == nil {
		dedupSensitive = make([]string, 0)
	}

	return SurfaceResult{
		TotalRoutes:     len(nodes),
		Nodes:           nodes,
		Edges:           edges,
		Technologies:    techs,
		SensitiveRoutes: dedupSensitive,
		ExternalDomains: externalDomains,
		RiskScore:       riskScore,
	}
}

func fingerprintTechnologies(headers FlexibleHeaders, content string) []TechFinger {
	techs := make([]TechFinger, 0)
	seen := make(map[string]bool)

	addTech := func(name, cat, evidence string) {
		if !seen[name] {
			seen[name] = true
			techs = append(techs, TechFinger{
				Name:     name,
				Category: cat,
				Evidence: evidence,
			})
		}
	}

	contentLower := strings.ToLower(content)

	// Framework Checks
	if strings.Contains(contentLower, "_next/static") || strings.Contains(contentLower, "__next_data__") {
		addTech("Next.js", "Frontend Framework", "Next.js static bundle script signature")
	}
	if strings.Contains(contentLower, "react-dom") || strings.Contains(contentLower, "data-reactroot") {
		addTech("React", "UI Library", "React DOM / root attributes found")
	}
	if strings.Contains(contentLower, "data-v-") || strings.Contains(contentLower, "vue.js") {
		addTech("Vue.js", "Frontend Framework", "Vue scoped attributes or runtime detected")
	}
	if strings.Contains(contentLower, "ng-version") || strings.Contains(contentLower, "angular.js") {
		addTech("Angular", "Frontend Framework", "Angular version tag or runtime detected")
	}
	if strings.Contains(contentLower, "wp-content") || strings.Contains(contentLower, "wp-includes") {
		addTech("WordPress", "Content Management System", "wp-content/wp-includes directory path")
	}
	if strings.Contains(contentLower, "laravel_session") || strings.Contains(contentLower, "x-csrf-token") {
		addTech("Laravel", "Backend Framework", "Laravel session or CSRF convention")
	}
	if strings.Contains(contentLower, "csrftoken") && strings.Contains(contentLower, "django") {
		addTech("Django", "Backend Framework", "Django CSRF token signature")
	}

	// Header & Cookie Checks
	for k, vals := range headers {
		kLower := strings.ToLower(k)
		for _, v := range vals {
			vLower := strings.ToLower(v)
			if kLower == "server" {
				if strings.Contains(vLower, "cloudflare") {
					addTech("Cloudflare", "CDN / Reverse Proxy", fmt.Sprintf("Server: %s", v))
				} else if strings.Contains(vLower, "nginx") {
					addTech("Nginx", "Web Server", fmt.Sprintf("Server: %s", v))
				} else if strings.Contains(vLower, "apache") {
					addTech("Apache", "Web Server", fmt.Sprintf("Server: %s", v))
				} else if strings.Contains(vLower, "akamai") {
					addTech("Akamai", "CDN / Edge Platform", fmt.Sprintf("Server: %s", v))
				}
			}
			if kLower == "x-powered-by" {
				addTech(v, "Backend Platform", fmt.Sprintf("X-Powered-By: %s", v))
			}

			// Cookie-based Vendor Detection
			if kLower == "set-cookie" {
				cookieLower := strings.ToLower(v)
				if strings.Contains(cookieLower, "_abck") || strings.Contains(cookieLower, "bm_mi") ||
					strings.Contains(cookieLower, "bm_so") || strings.Contains(cookieLower, "bm_sz") ||
					strings.Contains(cookieLower, "akamai_session") {
					addTech("Akamai Bot Manager", "Bot Protection / WAF", "Akamai Bot Manager cookies detected")
				}
				if strings.Contains(cookieLower, "mbox") || strings.Contains(cookieLower, "amcv") {
					addTech("Adobe Experience Cloud", "Marketing / Analytics", "Adobe Experience Cloud cookies detected")
				}
			}
		}
	}

	// Script-based Vendor Detection
	if strings.Contains(contentLower, "utag.sync") || strings.Contains(contentLower, "utag.js") ||
		strings.Contains(contentLower, "tealium") {
		addTech("Tealium iQ", "Tag Management", "Tealium iQ Tag Management detected")
	}

	return techs
}

func inferFindingCategory(f FindingPayload) string {
	cat := strings.ToUpper(strings.TrimSpace(f.Category))
	if cat != "" {
		return cat
	}
	t := strings.ToLower(f.Title)
	if strings.Contains(t, "cookie") {
		return "COOKIES"
	}
	if strings.Contains(t, "csp") || strings.Contains(t, "cors") || strings.Contains(t, "hsts") ||
		strings.Contains(t, "referrer") || strings.Contains(t, "permissions") || strings.Contains(t, "frame") ||
		strings.Contains(t, "nosniff") || strings.Contains(t, "server") || strings.Contains(t, "powered") {
		return "HEADERS"
	}
	if strings.Contains(t, "secret") || strings.Contains(t, "key") || strings.Contains(t, "token") {
		return "SECRETS"
	}
	if strings.Contains(t, "dom") || strings.Contains(t, "xss") || strings.Contains(t, "postmessage") {
		return "DOM_XSS"
	}
	if strings.Contains(t, "graphql") || strings.Contains(t, "swagger") || strings.Contains(t, "openapi") ||
		strings.Contains(t, "actuator") || strings.Contains(t, ".git") || strings.Contains(t, ".env") {
		return "API_EXPOSURE"
	}
	return "GENERAL"
}

func calculateRiskScore(baseScore int, sensitiveRoutesCount int, findings []FindingPayload) int {
	if len(findings) == 0 {
		if baseScore > 100 {
			return 100
		}
		if baseScore < 0 {
			return 0
		}
		return baseScore
	}

	severityWeights := map[string]int{
		"CRITICAL": 25,
		"HIGH":     15,
		"MEDIUM":   6,
		"LOW":      2,
	}
	categoryCaps := map[string]int{
		"COOKIES": 15,
		"HEADERS": 15,
	}

	catWeights := make(map[string][]int)
	catCrits := make(map[string]int)
	critCount := 0
	vendorOrInfoCount := 0

	for _, f := range findings {
		isVendor := f.VendorContext != "" || strings.HasPrefix(strings.ToLower(f.Title), "[third-party]")
		for _, tag := range f.Tags {
			if tag == "third_party" || tag == "vendor_integration" || tag == "vendor_script" {
				isVendor = true
				break
			}
		}

		sev := strings.ToUpper(strings.TrimSpace(f.Severity))
		if isVendor || sev == "INFO" {
			vendorOrInfoCount++
			continue
		}
		w, ok := severityWeights[sev]
		if !ok {
			continue
		}
		cat := inferFindingCategory(f)
		if sev == "CRITICAL" {
			critCount++
			catCrits[cat]++
		}
		catWeights[cat] = append(catWeights[cat], w)
	}

	totalCategoryImpact := 0
	activeCatImpact := 0
	for cat, weights := range catWeights {
		sort.Slice(weights, func(i, j int) bool { return weights[i] > weights[j] })
		catSum := 0
		for idx, w := range weights {
			var contrib int
			if idx == 0 {
				contrib = w
			} else if idx == 1 {
				contrib = w / 2
				if contrib < 1 {
					contrib = 1
				}
			} else {
				contrib = w / 4
				if contrib < 1 {
					contrib = 1
				}
			}
			catSum += contrib
		}
		capVal, hasCap := categoryCaps[cat]
		if !hasCap {
			capVal = 60
		} else if catCrits[cat] > 0 {
			critCap := catCrits[cat] * 25
			if critCap > capVal {
				capVal = critCap
			}
			if capVal > 60 {
				capVal = 60
			}
		}
		if catSum > capVal {
			catSum = capVal
		}
		totalCategoryImpact += catSum
		if cat != "COOKIES" && cat != "HEADERS" {
			activeCatImpact += catSum
		}
	}

	vendorImpact := 0
	if vendorOrInfoCount > 0 {
		vendorImpact = 1
		if vendorOrInfoCount >= 5 {
			vendorImpact = 2
		}
	}

	riskScore := baseScore
	composite := (baseScore / 2) + totalCategoryImpact + vendorImpact
	if composite > riskScore {
		riskScore = composite
	}

	hasActiveOrCritical := critCount > 0 || activeCatImpact > 0
	if !hasActiveOrCritical && sensitiveRoutesCount == 0 && riskScore > 40 {
		riskScore = 40
	}

	if riskScore > 100 {
		return 100
	}
	if riskScore < 0 {
		return 0
	}
	return riskScore
}

func deduplicate(items []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}
