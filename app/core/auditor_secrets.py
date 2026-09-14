import math
import re
from collections import Counter
from typing import Dict, List, Any

def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy H(X) of a string:
    H(X) = -sum(p(x) * log2(p(x)))
    Measures the randomness/information density in bits per character.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 2)


SECRET_RULES = [
    {
        "id": "AWS_KEY",
        "title": "Exposed AWS Access Key ID",
        "regex": re.compile(r'(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)'),
        "severity": "CRITICAL",
        "min_entropy": 3.0,
        "description": "Hardcoded Amazon Web Services (AWS) Access Key ID discovered in client-side web assets.",
        "remediation": "Revoke the exposed key in AWS IAM immediately, rotate credentials, and store secrets exclusively on backend servers."
    },
    {
        "id": "GOOGLE_API_KEY",
        "title": "Exposed Google Cloud / Firebase API Key",
        "regex": re.compile(r'(AIza[0-9A-Za-z\-_]{35})'),
        "severity": "HIGH",
        "min_entropy": 3.2,
        "description": "Hardcoded Google Cloud or Firebase API Key detected in client-side script.",
        "remediation": "Restrict the API key within Google Cloud Console to authorized HTTP referrers and necessary APIs only."
    },
    {
        "id": "STRIPE_SECRET_KEY",
        "title": "Exposed Stripe Secret Key",
        "regex": re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'),
        "severity": "CRITICAL",
        "min_entropy": 3.4,
        "description": "Live Stripe Secret Key exposed in client-facing code. Allows full programmatic access to payment processing.",
        "remediation": "Immediately roll the secret key in the Stripe Dashboard and ensure secret keys are never included in front-end builds."
    },
    {
        "id": "STRIPE_PUB_KEY",
        "title": "Stripe Publishable Key Identified",
        "regex": re.compile(r'(pk_live_[0-9a-zA-Z]{24,})'),
        "severity": "INFO",
        "min_entropy": 3.0,
        "description": "Live Stripe Publishable Key found. This is standard for client checkout but noted for surface inventory.",
        "remediation": "Confirm this publishable key is intended for this domain."
    },
    {
        "id": "GITHUB_TOKEN",
        "title": "Exposed GitHub Personal Access Token",
        "regex": re.compile(r'(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})'),
        "severity": "CRITICAL",
        "min_entropy": 3.2,
        "description": "Active GitHub Personal Access Token detected in client code.",
        "remediation": "Revoke the token immediately on GitHub, audit recent commit and repo access logs, and rotate."
    },
    {
        "id": "GITLAB_TOKEN",
        "title": "Exposed GitLab Personal Access Token",
        "regex": re.compile(r'(glpat-[0-9a-zA-Z\-_]{20})'),
        "severity": "CRITICAL",
        "min_entropy": 3.2,
        "description": "GitLab Personal Access Token exposed in client-side assets.",
        "remediation": "Revoke the token in GitLab User Settings immediately."
    },
    {
        "id": "SLACK_WEBHOOK",
        "title": "Exposed Slack Incoming Webhook",
        "regex": re.compile(r'(https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+)'),
        "severity": "HIGH",
        "min_entropy": 0.0,
        "description": "Incoming Slack webhook URL exposed, allowing unauthorized parties to post messages to internal channels.",
        "remediation": "Delete and recreate the webhook in Slack App Management; route notifications through a secure backend proxy."
    },
    {
        "id": "OPENAI_KEY",
        "title": "Exposed OpenAI / Anthropic API Key",
        "regex": re.compile(r'(sk-(?:proj-|ant-)?[a-zA-Z0-9\-_]{32,})'),
        "severity": "CRITICAL",
        "min_entropy": 3.2,
        "description": "LLM Provider API Key exposed in client-side web application.",
        "remediation": "Revoke and regenerate the API key in the provider console; proxy AI API requests through an authenticated backend API."
    },
    {
        "id": "JWT_TOKEN",
        "title": "Exposed JSON Web Token (JWT)",
        "regex": re.compile(r'(eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_+/=]{10,})'),
        "severity": "HIGH",
        "min_entropy": 3.4,
        "description": "Hardcoded JSON Web Token (JWT) detected in script or markup.",
        "remediation": "Inspect whether this JWT contains privileged claims or static credentials, and ensure tokens are issued dynamically."
    },
    {
        "id": "PRIVATE_KEY",
        "title": "Exposed Cryptographic Private Key",
        "regex": re.compile(r'(-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP)?\s*PRIVATE KEY-----[^\-]+-----END (?:RSA|OPENSSH|EC|DSA|PGP)?\s*PRIVATE KEY-----)', re.DOTALL),
        "severity": "CRITICAL",
        "min_entropy": 0.0,
        "description": "Asymmetric private key block embedded directly in web asset.",
        "remediation": "Remove the private key immediately, assume the key pair is compromised, and re-generate certificates."
    },
    {
        "id": "DATABASE_URI",
        "title": "Exposed Database Connection URI",
        "regex": re.compile(r'((?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql)://[a-zA-Z0-9_]+:[^@\s"\'<>]+@[a-zA-Z0-9\-_.]+(?::[0-9]+)?/[a-zA-Z0-9\-_]+)'),
        "severity": "CRITICAL",
        "min_entropy": 0.0,
        "description": "Database connection string containing credentials discovered in client assets.",
        "remediation": "Revoke database user credentials immediately and isolate database access within a private network VPC."
    }
]

class SecretAuditor:
    """Scans content strings (HTML, JavaScript, JSON) for credential leaks and sensitive tokens."""

    @staticmethod
    def audit_content(source_url: str, content: str, shadow_mode: bool = False) -> List[Dict[str, Any]]:
        findings = []
        if not content or len(content) < 10:
            return findings

        for rule in SECRET_RULES:
            matches = rule["regex"].finditer(content)
            for match in matches:
                secret_text = match.group(1) if match.groups() else match.group(0)

                # Calculate Shannon Entropy
                entropy = calculate_shannon_entropy(secret_text)
                min_ent = rule.get("min_entropy", 0.0)

                # Entropy False-Positive Filter:
                # If secret is repetitive/low-entropy (e.g. AKIAAAAAAAAAAAAAAAAA or test strings)
                is_low_entropy = min_ent > 0 and entropy < min_ent

                if is_low_entropy and not shadow_mode:
                    # Suppress false positive template / dummy strings
                    continue

                # Obfuscate secret for safe evidence presentation
                if len(secret_text) > 12:
                    obfuscated = secret_text[:4] + ("*" * (len(secret_text) - 8)) + secret_text[-4:]
                else:
                    obfuscated = secret_text[:2] + ("*" * (len(secret_text) - 4)) + secret_text[-2:]

                # Extract surrounding snippet
                start = max(0, match.start() - 40)
                end = min(len(content), match.end() + 40)
                snippet = content[start:end].replace("\n", " ").strip()

                sev = rule["severity"]
                conf = 0.95
                title = rule["title"]

                if is_low_entropy:
                    sev = "INFO"
                    conf = 0.30
                    title = f"{title} (Low Entropy / Probable Mock)"

                findings.append({
                    "severity": sev,
                    "category": "SECRETS",
                    "title": title,
                    "description": rule["description"],
                    "endpoint": source_url,
                    "evidence": f"Pattern: {rule['id']} | Token: {obfuscated} | Entropy: {entropy} bits/char (Threshold: {min_ent}) | Context: {snippet[:120]}",
                    "confidence": conf,
                    "remediation": rule["remediation"]
                })
                # Avoid flooding with duplicates of the exact same token in the same file
                break

        return findings
