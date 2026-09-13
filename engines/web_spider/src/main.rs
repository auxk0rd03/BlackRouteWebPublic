use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::Path;
use std::process;

#[derive(Serialize, Clone)]
struct EndpointFinding {
    file_path: String,
    line_number: usize,
    content: String,
    confidence: f64,
    #[serde(rename = "type")]
    finding_type: String,
    method: String,
    path: String,
}

#[derive(Serialize, Default)]
struct FormFinding {
    action: String,
    method: String,
}

#[derive(Serialize)]
struct SpiderResult {
    target_path: String,
    total_endpoints: usize,
    endpoints: Vec<EndpointFinding>,
    links: Vec<String>,
    scripts: Vec<String>,
    forms: Vec<FormFinding>,
}

const JUNK_EXTENSIONS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".woff", ".woff2",
    ".ttf", ".css", ".scss", ".less", ".mp4", ".webm", ".avi", ".mp3",
];

const JUNK_PATHS: &[&str] = &[
    "/static/css/", "/assets/fonts/", "http://www.w3.org", "https://schema.org",
    "facebook.com", "twitter.com", "linkedin.com", "instagram.com", "youtube.com",
    "google-analytics.com", "googletagmanager.com",
];

const HIGH_VALUE_KEYWORDS: &[&str] = &[
    "/api/", "/v1/", "/v2/", "/v3/", "graphql", "metrics",
    "admin", "auth", "token", "secret", "config", "internal", "actuator",
];

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: web_spider <file_path | dir <directory>>");
        process::exit(1);
    }

    if args[1] == "dir" {
        if args.len() < 3 {
            eprintln!("Usage: web_spider dir <directory>");
            process::exit(1);
        }
        let dir_path = &args[2];
        let result = process_directory(dir_path);
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else {
        let file_path = &args[1];
        let result = process_file(file_path);
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    }
}

fn process_directory(dir_path: &str) -> SpiderResult {
    let mut combined = SpiderResult {
        target_path: dir_path.to_string(),
        total_endpoints: 0,
        endpoints: Vec::new(),
        links: Vec::new(),
        scripts: Vec::new(),
        forms: Vec::new(),
    };

    let mut seen_paths: HashSet<String> = HashSet::new();

    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let file_res = process_file(path.to_str().unwrap_or(""));
                for ep in file_res.endpoints {
                    if !seen_paths.contains(&ep.path) {
                        seen_paths.insert(ep.path.clone());
                        combined.endpoints.push(ep);
                    }
                }
                combined.links.extend(file_res.links);
                combined.scripts.extend(file_res.scripts);
                combined.forms.extend(file_res.forms);
            }
        }
    }

    combined.total_endpoints = combined.endpoints.len();
    combined
}

fn process_file(file_path: &str) -> SpiderResult {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => match fs::read(file_path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => {
                let err = serde_json::json!({"error": format!("Failed to read file {}: {}", file_path, e)});
                println!("{}", err);
                process::exit(1);
            }
        },
    };

    let is_html = file_path.ends_with(".html") || file_path.ends_with(".htm") || content.contains("<html") || content.contains("<!DOCTYPE");
    
    let mut endpoints = Vec::new();
    let mut links = Vec::new();
    let mut scripts = Vec::new();
    let mut forms = Vec::new();

    if is_html {
        extract_html_assets(&content, &mut links, &mut scripts, &mut forms);
    }

    // Extract endpoint patterns using linear-time regex
    extract_endpoint_patterns(file_path, &content, &mut endpoints);

    SpiderResult {
        target_path: file_path.to_string(),
        total_endpoints: endpoints.len(),
        endpoints,
        links,
        scripts,
        forms,
    }
}

fn extract_html_assets(
    content: &str,
    links: &mut Vec<String>,
    scripts: &mut Vec<String>,
    forms: &mut Vec<FormFinding>,
) {
    let a_href_re = Regex::new(r##"(?i)<a\s+[^>]*href\s*=\s*['"]([^'"#\s>]+)['"]"##).unwrap();
    for cap in a_href_re.captures_iter(content) {
        if let Some(href) = cap.get(1) {
            let h = href.as_str().trim();
            if !h.is_empty() && !h.starts_with("javascript:") && !h.starts_with("mailto:") {
                links.push(h.to_string());
            }
        }
    }

    let script_src_re = Regex::new(r#"(?i)<script\s+[^>]*src\s*=\s*['"]([^'">\s]+)['"]"#).unwrap();
    for cap in script_src_re.captures_iter(content) {
        if let Some(src) = cap.get(1) {
            scripts.push(src.as_str().trim().to_string());
        }
    }

    let form_re = Regex::new(r#"(?i)<form\s+([^>]+)>"#).unwrap();
    let action_re = Regex::new(r#"(?i)action\s*=\s*['"]([^'"]*)['"]"#).unwrap();
    let method_re = Regex::new(r#"(?i)method\s*=\s*['"]([a-zA-Z]+)['"]"#).unwrap();

    for cap in form_re.captures_iter(content) {
        let attrs = cap.get(1).map_or("", |m| m.as_str());
        let action = action_re.captures(attrs).and_then(|c| c.get(1)).map_or("/", |m| m.as_str());
        let method = method_re.captures(attrs).and_then(|c| c.get(1)).map_or("GET", |m| m.as_str());

        forms.push(FormFinding {
            action: action.to_string(),
            method: method.to_uppercase(),
        });
    }
}

fn extract_endpoint_patterns(file_path: &str, content: &str, endpoints: &mut Vec<EndpointFinding>) {
    let is_minified = content.len() > 1000 && content.matches('\n').count() < 5;

    // Matches quoted paths starting with / or http(s):// or ws(s)://
    let pattern = Regex::new(r#"['"]((?:/|https?://|wss?://)[a-zA-Z0-9_?&=/\-\.:%]+)['"]"#).unwrap();
    let mut seen_paths: HashMap<String, usize> = HashMap::new();

    for mat in pattern.find_iter(content) {
        let raw_match = mat.as_str();
        let path = &raw_match[1..raw_match.len() - 1];

        if path.len() < 3 {
            continue;
        }

        let path_lower = path.to_lowercase();
        if JUNK_EXTENSIONS.iter().any(|ext| path_lower.ends_with(ext)) {
            continue;
        }
        if JUNK_PATHS.iter().any(|junk| path_lower.contains(junk)) {
            continue;
        }

        if let Some(idx) = seen_paths.get(path) {
            if let Some(finding) = endpoints.get_mut(*idx) {
                if finding.confidence < 0.9 && HIGH_VALUE_KEYWORDS.iter().any(|k| path_lower.contains(k)) {
                    finding.confidence = 0.95;
                }
            }
            continue;
        }

        let mut confidence = 0.45;
        let mut finding_type = "endpoint".to_string();

        if HIGH_VALUE_KEYWORDS.iter().any(|k| path_lower.contains(k)) {
            confidence = 0.90;
            finding_type = "api_endpoint".to_string();
        } else if path.ends_with(".json") || path.ends_with(".xml") {
            confidence = 0.75;
            finding_type = "data_endpoint".to_string();
        } else if path.starts_with("ws://") || path.starts_with("wss://") {
            confidence = 0.95;
            finding_type = "websocket_endpoint".to_string();
        }

        let line_number = if is_minified {
            1
        } else {
            content[..mat.start()].matches('\n').count() + 1
        };

        let start = mat.start().saturating_sub(40);
        let end = (mat.end() + 60).min(content.len());
        let mut snippet = content[start..end].replace('\n', " ").trim().to_string();
        if snippet.len() > 140 {
            snippet = format!("{}...", &snippet[..137]);
        }

        let finding = EndpointFinding {
            file_path: file_path.to_string(),
            line_number,
            content: snippet,
            confidence,
            finding_type,
            method: "DISCOVERED".to_string(),
            path: path.to_string(),
        };

        let idx = endpoints.len();
        seen_paths.insert(path.to_string(), idx);
        endpoints.push(finding);
    }
}
