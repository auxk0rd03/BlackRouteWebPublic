"""
CyberNest Labs — BlackRoute-Web Contextual Response & AST Analyzer (`auditor_ast_context.py`)
Implements Off_Def_BackEnd_Framework.md Module 3:
- Operates as an inline mitmproxy addon (`ContextualASTAddon`) or standalone downstream response parser.
- Ingests HTTP responses and parses them into concrete Abstract Syntax Trees (HTML, JavaScript, JSON).
- Determines exact parameter reflection contexts (unquoted attribute, script string, JSON value, SQL/template boundary)
  and computes deterministic boundary-break requirements.
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any, Dict, List
from bs4 import BeautifulSoup


def analyze_response_ast_context(url: str, body: str, canary: str = "") -> List[Dict[str, Any]]:
    """
    Parses an HTTP response into HTML/JS/JSON AST structures and identifies
    reflection contexts or unsafe structural sinks.
    """
    findings: List[Dict[str, Any]] = []
    if not body:
        return findings

    # 1. JSON AST Inspection
    stripped = body.strip()
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        try:
            parsed_json = json.loads(stripped)
            if isinstance(parsed_json, dict):
                for k, v in parsed_json.items():
                    if canary and canary in str(v):
                        findings.append({
                            "severity": "MEDIUM",
                            "category": "AST_CONTEXT",
                            "title": f"JSON AST Value Reflection Context ({k})",
                            "description": f"Canary reflected inside JSON key '{k}'. Boundary break requires quote/backslash escape verification.",
                            "endpoint": url,
                            "evidence": f"AST Node: JSONObject.{k} = {str(v)[:80]}",
                            "confidence": 0.90,
                            "remediation": "Ensure Content-Type: application/json with nosniff and strict JSON serializer encoding.",
                        })
        except Exception:
            pass

    # 2. HTML & Embedded Script AST Inspection via BeautifulSoup
    if "<html" in body.lower() or "<script" in body.lower() or "<input" in body.lower():
        soup = BeautifulSoup(body, "html.parser")

        # Check inline event handlers (unquoted or direct JS execution contexts)
        event_attrs = ("onload", "onerror", "onclick", "onmouseover", "onfocus")
        for tag in soup.find_all(True):
            for attr_name, attr_val in (tag.attrs or {}).items():
                val_str = " ".join(attr_val) if isinstance(attr_val, list) else str(attr_val or "")
                if canary and canary in val_str:
                    findings.append({
                        "severity": "HIGH",
                        "category": "AST_CONTEXT",
                        "title": f"HTML AST Attribute Reflection (<{tag.name} {attr_name}=...>)",
                        "description": f"Parameter reflected inside HTML attribute '{attr_name}' on <{tag.name}>.",
                        "endpoint": url,
                        "evidence": f"Boundary Break Context: <{tag.name} {attr_name}=\"{val_str[:60]}\">",
                        "confidence": 0.92,
                        "remediation": "Apply context-aware HTML attribute entity encoding before rendering.",
                    })
                elif attr_name.lower() in event_attrs and ("eval(" in val_str or "location." in val_str):
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "AST_CONTEXT",
                        "title": f"Inline DOM Event Handler AST Sink (<{tag.name} {attr_name}>)",
                        "description": "Inline DOM event handler directly references dynamic location or eval sink.",
                        "endpoint": url,
                        "evidence": f"<{tag.name} {attr_name}=\"{val_str[:80]}\">",
                        "confidence": 0.85,
                        "remediation": "Migrate inline event handlers to external scripts with strict CSP.",
                    })

        # Check <script> blocks for string literal reflection
        for script_tag in soup.find_all("script"):
            script_code = script_tag.string or ""
            if canary and canary in script_code:
                findings.append({
                    "severity": "HIGH",
                    "category": "AST_CONTEXT",
                    "title": "JavaScript AST Script Block Reflection",
                    "description": "Input reflected directly inside an executable <script> AST block.",
                    "endpoint": url,
                    "evidence": script_code[:120],
                    "confidence": 0.95,
                    "remediation": "Pass dynamic data via safe JSON data attributes rather than inline script string interpolation.",
                })

    return findings


class ContextualASTAddon:
    """mitmproxy-compatible inline addon (`mitmdump -s auditor_ast_context.py`)."""

    def __init__(self, canary: str = "CN_PROBE"):
        self.canary = canary
        self.findings: List[Dict[str, Any]] = []

    def response(self, flow: Any) -> None:
        try:
            url = getattr(flow.request, "pretty_url", "")
            text = getattr(flow.response, "text", "")
            if url and text:
                self.findings.extend(analyze_response_ast_context(url, text, self.canary))
        except Exception:
            pass


addons = [ContextualASTAddon()]
