use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
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

pub const DEFAULT_MAX_DEPTH: usize = 2;
pub const ABSOLUTE_MAX_DEPTH: usize = 3;
pub const MAX_HTML_PAGES: usize = 25;
pub const MAX_JS_FILES: usize = 50;

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
        eprintln!("Usage: web_spider <file_path | dir <directory>> [--depth <N>] [--domain <domain>]");
        process::exit(1);
    }

    let mut depth = DEFAULT_MAX_DEPTH;
    let mut domain = String::new();

    // Parse optional arguments
    let mut i = 1;
    let mut mode = String::new();
    let mut target = String::new();

    while i < args.len() {
        match args[i].as_str() {
            "dir" => {
                mode = "dir".to_string();
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    target = args[i + 1].clone();
                    i += 1;
                }
            }
            "--depth" => {
                if i + 1 < args.len() {
                    if let Ok(d) = args[i + 1].parse::<usize>() {
                        depth = d.clamp(1, ABSOLUTE_MAX_DEPTH);
                    }
                    i += 1;
                }
            }
            "--domain" => {
                if i + 1 < args.len() {
                    domain = args[i + 1].trim().to_lowercase();
                    i += 1;
                }
            }
            other => {
                if target.is_empty() && !other.starts_with("--") {
                    target = other.to_string();
                }
            }
        }
        i += 1;
    }

    if target.is_empty() {
        eprintln!("Missing target file or directory");
        process::exit(1);
    }

    if mode == "dir" || Path::new(&target).is_dir() {
        let result = process_directory_bfs(&target, depth, &domain);
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else {
        let result = process_file(&target, &domain);
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    }
}

pub fn is_allowed_domain(url: &str, target_domain: &str) -> bool {
    if target_domain.is_empty() {
        return true;
    }
    let t_lower = target_domain.to_lowercase();
    if url.starts_with('/') && !url.starts_with("//") {
        return true;
    }

    let host = if let Some(idx) = url.find("://") {
        let rest = &url[idx + 3..];
        rest.split('/').next().unwrap_or("").split(':').next().unwrap_or("")
    } else if url.starts_with("//") {
        let rest = &url[2..];
        rest.split('/').next().unwrap_or("").split(':').next().unwrap_or("")
    } else {
        return true;
    };

    let h_lower = host.to_lowercase();
    h_lower == t_lower || h_lower.ends_with(&format!(".{}", t_lower))
}

fn process_directory_bfs(dir_path: &str, max_depth: usize, target_domain: &str) -> SpiderResult {
    let mut combined = SpiderResult {
        target_path: dir_path.to_string(),
        total_endpoints: 0,
        endpoints: Vec::new(),
        links: Vec::new(),
        scripts: Vec::new(),
        forms: Vec::new(),
    };

    let mut seen_paths: HashSet<String> = HashSet::new();
    let mut seen_links: HashSet<String> = HashSet::new();
    let mut seen_scripts: HashSet<String> = HashSet::new();

    let mut html_pages_processed = 0;
    let mut js_files_processed = 0;

    // Bounded BFS queue for directory hierarchy traversal: (path, current_depth)
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    let raw_root = PathBuf::from(dir_path);
    if !raw_root.exists() {
        return combined;
    }
    if let Ok(meta) = fs::symlink_metadata(&raw_root) {
        if meta.file_type().is_symlink() {
            return combined;
        }
    }
    let canon_root = fs::canonicalize(&raw_root).unwrap_or_else(|_| raw_root.clone());
    queue.push_back((canon_root.clone(), 0));

    while let Some((curr_path, curr_depth)) = queue.pop_front() {
        if curr_path.is_dir() {
            if curr_depth > max_depth {
                continue;
            }
            if let Ok(entries) = fs::read_dir(&curr_path) {
                for entry in entries.flatten() {
                    if let Ok(ft) = entry.file_type() {
                        if ft.is_symlink() {
                            continue;
                        }
                    }
                    let child_path = entry.path();
                    if let Ok(canon_child) = fs::canonicalize(&child_path) {
                        if !canon_child.starts_with(&canon_root) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    if child_path.is_dir() && curr_depth + 1 <= max_depth {
                        queue.push_back((child_path, curr_depth + 1));
                    } else if child_path.is_file() {
                        let fname = child_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        let is_html = fname.ends_with(".html") || fname.ends_with(".htm");
                        let is_js = fname.ends_with(".js");

                        if is_html && html_pages_processed >= MAX_HTML_PAGES {
                            continue;
                        }
                        if is_js && js_files_processed >= MAX_JS_FILES {
                            continue;
                        }

                        if is_html {
                            html_pages_processed += 1;
                        } else if is_js {
                            js_files_processed += 1;
                        }

                        let file_res = process_file(child_path.to_str().unwrap_or(""), target_domain);

                        for ep in file_res.endpoints {
                            if !seen_paths.contains(&ep.path) {
                                seen_paths.insert(ep.path.clone());
                                combined.endpoints.push(ep);
                            }
                        }

                        for link in file_res.links {
                            if !seen_links.contains(&link) && is_allowed_domain(&link, target_domain) {
                                seen_links.insert(link.clone());
                                combined.links.push(link);
                            }
                        }

                        for script in file_res.scripts {
                            if !seen_scripts.contains(&script) {
                                seen_scripts.insert(script.clone());
                                combined.scripts.push(script);
                            }
                        }

                        combined.forms.extend(file_res.forms);
                    }
                }
            }
        }
    }

    combined.total_endpoints = combined.endpoints.len();
    combined
}

fn process_file(file_path: &str, target_domain: &str) -> SpiderResult {
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
        extract_html_assets(&content, &mut links, &mut scripts, &mut forms, target_domain);
    }

    // Extract dynamic chunk manifests & Webpack/Vite runtime maps
    extract_chunk_manifests(&content, &mut scripts);

    // Extract endpoint patterns using linear-time regex
    extract_endpoint_patterns(file_path, &content, &mut endpoints, target_domain);
    
    // Extract dynamic routes (GraphQL and REST)
    extract_dynamic_routes(&content, &mut endpoints, file_path);

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
    target_domain: &str,
) {
    let a_href_re = Regex::new(r##"(?i)<a\s+[^>]*href\s*=\s*['"]([^'"#\s>]+)['"]"##).unwrap();
    for cap in a_href_re.captures_iter(content) {
        if let Some(href) = cap.get(1) {
            let h = href.as_str().trim();
            if !h.is_empty() 
                && !h.starts_with("javascript:") 
                && !h.starts_with("mailto:") 
                && is_allowed_domain(h, target_domain) 
            {
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

fn resolve_webpack_chunks(content: &str, scripts: &mut Vec<String>) {
    // 1. Locate Webpack dynamic chunk maps: __webpack_require__.u or jsonpScriptSrc
    let needles = ["__webpack_require__.u", "jsonpScriptSrc"];
    for needle in &needles {
        let mut start_idx = 0;
        while let Some(rel_idx) = content[start_idx..].find(needle) {
            let found_idx = start_idx + rel_idx;
            let end_idx = (found_idx + 1500).min(content.len());
            let slice = &content[found_idx..end_idx];

            let suffix = if slice.contains(".chunk.js") {
                ".chunk.js"
            } else if slice.contains(".bundle.js") {
                ".bundle.js"
            } else {
                ".js"
            };

            let prefix_re = Regex::new(r#"['"]((?:static/|assets/)?js/?)['"]"#).unwrap();
            let prefix = prefix_re.captures(slice).and_then(|c| c.get(1)).map_or("", |m| m.as_str());

            let map_entry_re = Regex::new(r#"(?:"?([a-zA-Z0-9_\-]+)"?\s*:\s*["']([a-zA-Z0-9_\-]+)["'])"#).unwrap();
            for entry in map_entry_re.captures_iter(slice) {
                if let (Some(cid), Some(hash)) = (entry.get(1), entry.get(2)) {
                    let chunk_id = cid.as_str();
                    let hash_val = hash.as_str();

                    let resolved_name = format!("{}{}.{}{}", prefix, chunk_id, hash_val, suffix);
                    if !scripts.contains(&resolved_name) {
                        scripts.push(resolved_name);
                    }
                    let alt_name = format!("{}{}{}", prefix, hash_val, suffix);
                    if !scripts.contains(&alt_name) && hash_val.len() > 6 {
                        scripts.push(alt_name);
                    }
                }
            }

            start_idx = found_idx + needle.len();
        }
    }

    // 2. Vite / Rollup dynamic chunk imports: import("./assets/foo.js") or import('/assets/foo.js')
    let vite_dyn_re = Regex::new(r#"import\s*\(\s*['"]([^'"]+\.js)['"]\s*\)"#).unwrap();
    for cap in vite_dyn_re.captures_iter(content) {
        if let Some(m) = cap.get(1) {
            let path = m.as_str().to_string();
            if !scripts.contains(&path) {
                scripts.push(path.clone());
            }
            let trimmed = path.trim_start_matches("./").to_string();
            if !scripts.contains(&trimmed) {
                scripts.push(trimmed);
            }
        }
    }

    // 3. Rollup dynamic chunk preload pattern: preload(["assets/chunk1.js", "assets/chunk2.js"])
    let rollup_preload_re = Regex::new(r#"preload\s*\(\s*\[([^\]]+)\]"#).unwrap();
    let quoted_re = Regex::new(r#"['"]([^'"]+\.js)['"]"#).unwrap();
    for cap in rollup_preload_re.captures_iter(content) {
        if let Some(arr) = cap.get(1) {
            for q_cap in quoted_re.captures_iter(arr.as_str()) {
                if let Some(s) = q_cap.get(1) {
                    let script_str = s.as_str().trim().to_string();
                    if !scripts.contains(&script_str) {
                        scripts.push(script_str);
                    }
                }
            }
        }
    }
}

fn extract_chunk_manifests(content: &str, scripts: &mut Vec<String>) {
    // 1. Webpack runtime chunk resolver
    resolve_webpack_chunks(content, scripts);

    // 2. Standard Webpack/Vite chunk patterns
    let chunk_re = Regex::new(r#"['"]((?:/|https?://)[^'"]*chunk-[^'"]*\.js)['"]"#).unwrap();
    let runtime_re = Regex::new(r#"['"]((?:/|https?://)[^'"]*runtime~[^'"]*\.js)['"]"#).unwrap();
    let vendor_re = Regex::new(r#"['"]((?:/|https?://)[^'"]*vendors~[^'"]*\.js)['"]"#).unwrap();
    let main_re = Regex::new(r#"['"]((?:/|https?://)[^'"]*main[^'"]*\.js)['"]"#).unwrap();
    let app_re = Regex::new(r#"['"]((?:/|https?://)[^'"]*app[^'"]*\.js)['"]"#).unwrap();
    let index_re = Regex::new(r#"['"]((?:/|https?://)[^'"]*index[^'"]*\.js)['"]"#).unwrap();
    let hash_chunk_re = Regex::new(r#"['"]((?:/|https?://)[^'"]*[a-zA-Z0-9_-]+\.[a-f0-9]{8,}\.js)['"]"#).unwrap();
    let vite_chunk_re = Regex::new(r#"['"]((?:/|https?://)[^'"]*assets/[a-f0-9]{8}\.js)['"]"#).unwrap();
    let next_chunk_re = Regex::new(r#"['"]((?:/|https?://)[^'"]*_next/static/chunks/[^'"]*\.js)['"]"#).unwrap();
    let manifest_re = Regex::new(r#"['"]((?:/|https?://)[^'"]*manifest\.json)['"]"#).unwrap();
    
    let mut seen_chunks: HashSet<String> = scripts.iter().cloned().collect();
    
    for pattern in &[&chunk_re, &runtime_re, &vendor_re, &main_re, &app_re, &index_re, &hash_chunk_re, &vite_chunk_re, &next_chunk_re, &manifest_re] {
        for cap in pattern.captures_iter(content) {
            if let Some(chunk_url) = cap.get(1) {
                let url = chunk_url.as_str().trim();
                if !url.is_empty() && !seen_chunks.contains(url) {
                    seen_chunks.insert(url.to_string());
                    scripts.push(url.to_string());
                }
            }
        }
    }
    
    let webpack_chunk_loading_re = Regex::new(r#"__webpack_require__\.p\s*\+\s*['"]([^'"]+)['"]"#).unwrap();
    for cap in webpack_chunk_loading_re.captures_iter(content) {
        if let Some(chunk_base) = cap.get(1) {
            let base = chunk_base.as_str().trim();
            if !base.is_empty() && !seen_chunks.contains(base) {
                seen_chunks.insert(base.to_string());
                scripts.push(base.to_string());
            }
        }
    }
    
    if let Some(manifest_start) = content.find("window.__webpack_manifest__") {
        if let Some(manifest_end) = content[manifest_start..].find('}') {
            let manifest_content = &content[manifest_start..manifest_start + manifest_end + 1];
            let url_in_manifest_re = Regex::new(r#""([^"]*\.(?:js|json))""#).unwrap();
            for cap in url_in_manifest_re.captures_iter(manifest_content) {
                if let Some(url) = cap.get(1) {
                    let clean_url = url.as_str().trim();
                    if !clean_url.is_empty() && !seen_chunks.contains(clean_url) {
                        seen_chunks.insert(clean_url.to_string());
                        scripts.push(clean_url.to_string());
                    }
                }
            }
        }
    }
}

pub fn is_valid_endpoint(path: &str) -> bool {
    if path.is_empty() || path.len() > 256 {
        return false;
    }
    if !path.starts_with('/') && !path.starts_with("http://") && !path.starts_with("https://") && !path.starts_with("ws://") && !path.starts_with("wss://") {
        return false;
    }

    let invalid_tokens = [
        "&&", "||", "return", "function", "var ", "let ", "const ",
        "test(", "match(", "replace(", "typeof ", "undefined", "null",
        ";", "{", "}", "[", "]", "(", ")", "=>", "<", ">", "$", "\\",
        ",", " ", "\t", "\n", "\r", "\"", "'", "`",
    ];
    for token in invalid_tokens.iter() {
        if path.contains(token) {
            return false;
        }
    }

    if path.contains("d{") || path.contains("w{") || path.ends_with("/i") || path.ends_with("/g") {
        return false;
    }

    true
}

fn extract_dynamic_routes(content: &str, endpoints: &mut Vec<EndpointFinding>, file_path: &str) {
    let rest_param_re = Regex::new(r#"['"]((?:/|https?://)[a-zA-Z0-9_\-\./]*:[a-zA-Z0-9_]+[a-zA-Z0-9_\-\./]*)['"]"#).unwrap();
    let graphql_query_re = Regex::new(r"query\s+(\w+)[\s\{]").unwrap();
    let graphql_mutation_re = Regex::new(r"mutation\s+(\w+)[\s\{]").unwrap();
    
    let mut seen_paths: HashSet<String> = HashSet::new();
    
    for cap in rest_param_re.captures_iter(content) {
        if let Some(path) = cap.get(1) {
            let route = path.as_str().trim();
            if !seen_paths.contains(route) && route.len() > 5 && is_valid_endpoint(route) {
                seen_paths.insert(route.to_string());
                endpoints.push(EndpointFinding {
                    file_path: file_path.to_string(),
                    line_number: 1,
                    content: format!("Dynamic route detected: {}", route),
                    confidence: 0.85,
                    finding_type: "dynamic_rest_route".to_string(),
                    method: "REST".to_string(),
                    path: route.to_string(),
                });
            }
        }
    }
    
    for cap in graphql_query_re.captures_iter(content) {
        if let Some(query_name) = cap.get(1) {
            let name = query_name.as_str();
            if !seen_paths.contains(name) {
                seen_paths.insert(name.to_string());
                endpoints.push(EndpointFinding {
                    file_path: file_path.to_string(),
                    line_number: 1,
                    content: format!("GraphQL query detected: {}", name),
                    confidence: 0.90,
                    finding_type: "graphql_query".to_string(),
                    method: "GRAPHQL".to_string(),
                    path: format!("/graphql?query={}", name),
                });
            }
        }
    }
    
    for cap in graphql_mutation_re.captures_iter(content) {
        if let Some(mutation_name) = cap.get(1) {
            let name = mutation_name.as_str();
            if !seen_paths.contains(name) {
                seen_paths.insert(name.to_string());
                endpoints.push(EndpointFinding {
                    file_path: file_path.to_string(),
                    line_number: 1,
                    content: format!("GraphQL mutation detected: {}", name),
                    confidence: 0.90,
                    finding_type: "graphql_mutation".to_string(),
                    method: "GRAPHQL".to_string(),
                    path: format!("/graphql?mutation={}", name),
                });
            }
        }
    }
}

fn extract_endpoint_patterns(file_path: &str, content: &str, endpoints: &mut Vec<EndpointFinding>, target_domain: &str) {
    let is_minified = content.len() > 1000 && content.matches('\n').count() < 5;
    let pattern = Regex::new(r#"['"]((?:/|https?://|wss?://)[a-zA-Z0-9_?&=/\-\.:%]+)['"]"#).unwrap();
    let mut seen_paths: HashMap<String, usize> = HashMap::new();

    for mat in pattern.find_iter(content) {
        let raw_match = mat.as_str();
        let path = &raw_match[1..raw_match.len() - 1];

        if path.len() < 3 || !is_valid_endpoint(path) {
            continue;
        }

        if !is_allowed_domain(path, target_domain) {
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
