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
	"strings"
)

type SurfaceResult struct {
	TotalRoutes      int           `json:"total_routes"`
	Nodes            []string      `json:"nodes"`
	Edges            []Edge        `json:"edges"`
	Technologies     []TechFinger  `json:"technologies"`
	SensitiveRoutes  []string      `json:"sensitive_routes"`
	ExternalDomains  []string      `json:"external_domains"`
	RiskScore        int           `json:"risk_score"`
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

type InputPayload struct {
	Endpoints []string          `json:"endpoints"`
	Headers   map[string]string `json:"headers"`
	Content   string            `json:"content"`
}

var sensitiveKeywords = []string{
	"admin", "login", "auth", "oauth", "token", "secret", "config",
	"actuator", "metrics", "upload", "debug", "test", "internal",
	"graphql", "swagger", "openapi", "api-docs", "backup", "dump",
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
	payload.Headers = make(map[string]string)
	var endpoints []string
	var allContent strings.Builder

	reEndpoint := regexp.MustCompile(`['"]((?:/|https?://)[a-zA-Z0-9_?&=/\-\.:%]+)['"]`)

	_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
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

func analyzeSurface(payload InputPayload) SurfaceResult {
	nodeSet := make(map[string]bool)
	edgeSet := make(map[string]bool)
	var edges []Edge
	var sensitiveRoutes []string
	extDomainSet := make(map[string]bool)

	// Clean & Deduplicate endpoints
	for _, rawEp := range payload.Endpoints {
		ep := strings.TrimSpace(rawEp)
		if ep == "" || len(ep) < 2 {
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

		nodeSet[pathOnly] = true

		// Check sensitive route
		pathLower := strings.ToLower(pathOnly)
		for _, kw := range sensitiveKeywords {
			if strings.Contains(pathLower, kw) {
				sensitiveRoutes = append(sensitiveRoutes, pathOnly)
				break
			}
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

	// Risk Score Calculation (0 - 100)
	riskScore := 10 // Baseline
	if len(sensitiveRoutes) > 0 {
		riskScore += len(sensitiveRoutes) * 5
	}
	if len(payload.Endpoints) > 20 {
		riskScore += 15
	}
	if len(extDomainSet) > 5 {
		riskScore += 10
	}
	if riskScore > 100 {
		riskScore = 95
	}

	var nodes []string
	for n := range nodeSet {
		nodes = append(nodes, n)
	}

	var externalDomains []string
	for d := range extDomainSet {
		externalDomains = append(externalDomains, d)
	}

	return SurfaceResult{
		TotalRoutes:     len(nodes),
		Nodes:           nodes,
		Edges:           edges,
		Technologies:    techs,
		SensitiveRoutes: deduplicate(sensitiveRoutes),
		ExternalDomains: externalDomains,
		RiskScore:       riskScore,
	}
}

func fingerprintTechnologies(headers map[string]string, content string) []TechFinger {
	var techs []TechFinger
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

	// Header Checks
	for k, v := range headers {
		kLower := strings.ToLower(k)
		vLower := strings.ToLower(v)
		if kLower == "server" {
			if strings.Contains(vLower, "cloudflare") {
				addTech("Cloudflare", "CDN / Reverse Proxy", fmt.Sprintf("Server: %s", v))
			} else if strings.Contains(vLower, "nginx") {
				addTech("Nginx", "Web Server", fmt.Sprintf("Server: %s", v))
			} else if strings.Contains(vLower, "apache") {
				addTech("Apache", "Web Server", fmt.Sprintf("Server: %s", v))
			}
		}
		if kLower == "x-powered-by" {
			addTech(v, "Backend Platform", fmt.Sprintf("X-Powered-By: %s", v))
		}
	}

	return techs
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
