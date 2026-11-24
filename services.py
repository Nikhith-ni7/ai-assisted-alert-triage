"""Read-only Sentinel, reputation lookups, and bounded LLM drafting."""
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
from uuid import UUID

from triage import STEPS, VERDICTS, normalize, validate_draft

ARM = "https://management.azure.com"
VERSION = "api-version=2025-09-01"
HOSTS = {"management.azure.com", "www.virustotal.com", "api.abuseipdb.com", "api.openai.com"}
OLLAMA = "http://127.0.0.1:11434/api/chat"
ENV_FILE = Path(__file__).resolve().parent / ".env"
REPUTATION_KEY_NAMES = ("VT_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")
CATEGORIES = {
    "password spray": "password_spray",
    "mfa push flooding": "mfa_push",
    "mfa fatigue followed by successful sign-in": "mfa_push",
    "new country": "new_country",
    "sign-in from a new country": "new_country",
    "impossible travel": "impossible_travel",
    "suspicious inbox rule": "inbox_rule",
    "high-risk successful sign-in": "risky_signin",
}


class ServiceError(Exception):
    def __init__(self, service, status=None, reason="unavailable"):
        self.status = status
        self.reason = reason
        super().__init__(f"{service} request failed" + (f" (HTTP {status})" if status else ""))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def tls_context():
    context = ssl.create_default_context()
    if (sys.platform == "darwin" and not context.get_ca_certs()
            and not (os.getenv("SSL_CERT_FILE") or os.getenv("SSL_CERT_DIR"))):
        system_bundle = Path("/etc/ssl/cert.pem")
        if system_bundle.is_file():
            context.load_verify_locations(cafile=str(system_bundle))
    return context


def request_json(url, headers, method="GET", payload=None):
    target = urlsplit(url)
    local = url == OLLAMA
    if not local and (target.scheme != "https" or target.hostname not in HOSTS
            or target.username is not None or target.password is not None
            or target.port not in (None, 443) or target.fragment):
        raise ValueError("Unapproved HTTPS destination")
    req = Request(url, data=None if payload is None else json.dumps(payload).encode(),
                  headers={"Accept": "application/json", "Content-Type": "application/json", **headers},
                  method=method)
    try:
        opener = (build_opener(NoRedirect(), ProxyHandler({})) if local
                  else build_opener(NoRedirect(), HTTPSHandler(context=tls_context())))
        with opener.open(req, timeout=60 if local else 20) as response:
            content = response.read(2_000_001)
        if len(content) > 2_000_000:
            raise ServiceError(target.hostname)
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ServiceError(target.hostname)
        return data
    except HTTPError as exc:
        exc.close()
        raise ServiceError(target.hostname, exc.code) from None
    except URLError as exc:
        reason = "tls_error" if isinstance(exc.reason, ssl.SSLError) else "network_error"
        raise ServiceError(target.hostname, reason=reason) from None
    except ssl.SSLError:
        raise ServiceError(target.hostname, reason="tls_error") from None
    except TimeoutError:
        raise ServiceError(target.hostname, reason="network_error") from None
    except ValueError:
        raise ServiceError(target.hostname, reason="invalid_response") from None


def object_value(value):
    return value if isinstance(value, dict) else {}


def items(data, key="value"):
    value = data.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ServiceError("Sentinel response")
    return value


def mapped_category(title):
    if not isinstance(title, str):
        return "unknown"
    return CATEGORIES.get(title.casefold().removeprefix("[synthetic] ").strip(), "unknown")


def sentinel_alerts(subscription, resource_group, workspace, token, incident_limit):
    subscription = str(UUID(subscription))
    if not re.fullmatch(r"[a-zA-Z0-9_.()-]{1,90}", resource_group) or resource_group.endswith("."):
        raise ValueError("Invalid resource group")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9-]{2,61}[a-zA-Z0-9]", workspace):
        raise ValueError("Invalid workspace name")
    if not 1 <= incident_limit <= 50:
        raise ValueError("Incident limit must be between 1 and 50")
    path = (f"/subscriptions/{subscription}/resourceGroups/{quote(resource_group, safe='')}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
            "/providers/Microsoft.SecurityInsights/incidents")
    headers = {"Authorization": f"Bearer {token}"}
    query = urlencode({"api-version": "2025-09-01", "$top": incident_limit,
                       "$orderby": "properties/createdTimeUtc desc"})
    url = f"{ARM}{path}?{query}"
    remaining = incident_limit
    seen_pages = set()
    seen_alerts = set()
    while url and remaining and len(seen_pages) < incident_limit:
        parts = urlsplit(url)
        if parts.netloc != "management.azure.com" or parts.path.casefold() != path.casefold():
            raise ValueError("Invalid Sentinel pagination destination")
        if url in seen_pages:
            raise ValueError("Repeated Sentinel pagination link")
        seen_pages.add(url)
        page = request_json(url, headers)
        for incident in items(page)[:remaining]:
            incident_id = str(UUID(incident["name"]))
            base = f"{ARM}{path}/{incident_id}"
            alerts = items(request_json(f"{base}/alerts?{VERSION}", headers, method="POST"))
            # Incident-level entity associations are ambiguous if several alerts share an incident.
            entities = items(request_json(f"{base}/entities?{VERSION}", headers, method="POST"), "entities") if len(alerts) == 1 else []
            ips, hashes = [], []
            for entity in entities:
                props = object_value(entity.get("properties"))
                if entity.get("kind") == "Ip":
                    ips.append(props.get("address"))
                elif entity.get("kind") == "FileHash":
                    hashes.append(props.get("hashValue"))
            for entry in alerts:
                props = object_value(entry.get("properties"))
                uid = props.get("systemAlertId") or entry.get("name")
                cooked = normalize({"id": uid, "category": mapped_category(props.get("alertDisplayName")),
                                    "severity": str(props.get("severity", "")).lower(),
                                    "ips": ips, "hashes": hashes}, source="sentinel_title_mapping")
                if cooked.alert_id not in seen_alerts:
                    seen_alerts.add(cooked.alert_id)
                    yield cooked
            remaining -= 1
        url = page.get("nextLink")
        if url is not None and not isinstance(url, str):
            raise ValueError("Invalid Sentinel pagination link")


def reputation_keys():
    local = {}
    try:
        with ENV_FILE.open(encoding="utf-8") as stream:
            contents = stream.read(16_385)
    except FileNotFoundError:
        contents = ""
    if len(contents) > 16_384:
        raise ValueError("The project .env exceeds the size limit")
    for line in contents.splitlines():
        name, separator, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if not separator or name not in REPUTATION_KEY_NAMES:
            continue
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1]
        if value and value not in {"...", "…"}:
            local[name] = value
    return {
        "vt": (os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
               or local.get("VT_API_KEY") or local.get("VIRUSTOTAL_API_KEY")),
        "abuseipdb": os.getenv("ABUSEIPDB_API_KEY") or local.get("ABUSEIPDB_API_KEY"),
    }


class Reputation:
    def __init__(self, budget=4):
        self.keys = reputation_keys()
        self.remaining = {"vt": budget, "abuseipdb": budget}
        self.cache = {}

    def lookup(self, provider, value):
        cached = self.cache.get((provider, value))
        if cached is not None:
            return cached
        key_type = "vt" if provider.startswith("vt_") else "abuseipdb"
        key = self.keys[key_type]
        if not key or not self.remaining[key_type]:
            return {"provider": provider, "status": "unavailable"}
        self.remaining[key_type] -= 1
        result = {"provider": provider, "status": "ok"}
        try:
            if key_type == "vt":
                collection = "files" if provider == "vt_hash" else "ip_addresses"
                payload = request_json(f"https://www.virustotal.com/api/v3/{collection}/{quote(value, safe='')}",
                                       {"x-apikey": key})
                attributes = object_value(object_value(payload.get("data")).get("attributes"))
                result["malicious"] = object_value(attributes.get("last_analysis_stats")).get("malicious")
            else:
                query = urlencode({"ipAddress": value, "maxAgeInDays": 30})
                payload = request_json(f"https://api.abuseipdb.com/api/v2/check?{query}", {"Key": key})
                result["score"] = object_value(payload.get("data")).get("abuseConfidenceScore")
        except ServiceError as exc:
            result["status"] = {401: "unauthorized", 403: "forbidden", 404: "not_found",
                                429: "rate_limited"}.get(exc.status, exc.reason)
            if exc.status in (401, 403, 429):
                self.remaining[key_type] = 0
        self.cache[(provider, value)] = result
        return result

    def enrich(self, alert):
        rows = []
        for ip in alert.ips:
            address = ipaddress.ip_address(ip)
            if address.is_global and not address.is_multicast:
                rows.extend(self.lookup(provider, ip) for provider in ("vt_ip", "abuseipdb"))
        rows.extend(self.lookup("vt_hash", value) for value in alert.hashes)
        return rows


def draft_messages(facts):
    catalog = {step: STEPS[step] for step in facts.get("allowed_steps", [])}
    policy = (
        "You assist a SOC analyst. From the evidence JSON, write a short triage note. Do not invent "
        "events. Category and severity are not proof. Missing reputation is unknown, and reputation "
        "alone is not proof of compromise. Weigh combinations: a new device, a hosting or VPN IP, "
        "an admin account, a very new account, or an Office application starting a script host "
        "matter more together than alone. Documented benign context (verified change, corporate "
        "egress, user confirmation) can outweigh reputation. Return only a JSON object with keys "
        f"summary, verdict, techniques, steps. Verdict is one of {', '.join(VERDICTS)}; use needs_review "
        "for insufficient or conflicting evidence. techniques: only from allowed_techniques. "
        "steps: 1 to 4 step IDs from this catalog, most important first: "
        f"{json.dumps(catalog)}. summary: two short sentences on the evidence and the main "
        "uncertainty. No account actions."
    )
    return [{"role": "system", "content": policy}, {"role": "user", "content": json.dumps(facts)}]


def llm_draft(facts, model, api_key):
    response = request_json("https://api.openai.com/v1/chat/completions",
                            {"Authorization": f"Bearer {api_key}"}, payload={
                                "model": model, "store": False, "max_completion_tokens": 700,
                                "response_format": {"type": "json_object"},
                                "messages": draft_messages(facts),
                            }, method="POST")
    try:
        choice = response["choices"][0]
        if choice.get("finish_reason") != "stop" or choice["message"].get("refusal"):
            raise ValueError("Model did not complete a draft")
        result = json.loads(choice["message"]["content"])
        return validate_draft(result, facts["allowed_techniques"], facts.get("allowed_steps", ()))
    except (KeyError, TypeError, IndexError, AttributeError, ValueError):
        raise ValueError("Model response failed validation; no verdict recorded") from None


def ollama_draft(facts, model):
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,80}", model) or re.search(r"(?:-cloud|:cloud)(?:$|:)", model, re.I):
        raise ValueError("Choose a locally installed Ollama model tag")
    allowed = facts["allowed_techniques"]
    steps = facts.get("allowed_steps", [])
    schema = {
        "type": "object", "additionalProperties": False,
        "required": ["summary", "verdict", "techniques", "steps"],
        "properties": {
            "summary": {"type": "string", "minLength": 1, "maxLength": 1200},
            "verdict": {"type": "string", "enum": list(VERDICTS)},
            "techniques": {"type": "array", "maxItems": len(allowed),
                           "items": {"type": "string", **({"enum": allowed} if allowed else {})}},
            "steps": {"type": "array", "maxItems": min(4, len(steps)),
                      "items": {"type": "string", **({"enum": steps} if steps else {})}},
        },
    }
    response = request_json(OLLAMA, {}, method="POST", payload={
        "model": model, "stream": False, "think": False, "format": schema,
        "options": {"temperature": 0, "num_predict": 400, "num_ctx": 4096},
        "messages": draft_messages(facts),
    })
    try:
        if response.get("done") is not True or response.get("done_reason") == "length":
            raise ValueError("Model response was incomplete")
        return validate_draft(json.loads(response["message"]["content"]), allowed, steps)
    except (KeyError, TypeError, ValueError):
        raise ValueError("Local model response failed validation; no verdict recorded") from None


OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
LOLBINS = {"rundll32.exe", "regsvr32.exe", "certutil.exe", "procdump.exe", "procdump64.exe",
           "vssadmin.exe", "wmic.exe", "bitsadmin.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"}


def process_chain(parent, child):
    """Classify a parent/child pair from Sysmon paths. Only the class leaves this function."""
    if not isinstance(parent, str) or not isinstance(child, str) or not child:
        return "none"
    parent = parent.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    child = child.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    if child in SHELLS and parent in OFFICE:
        return "office_to_script"
    if child in SHELLS and parent == "explorer.exe":
        return "explorer_to_shell"
    if child in SHELLS and parent in BROWSERS:
        return "browser_to_shell"
    if child in SHELLS and parent in {"services.exe", "svchost.exe", "wmiprvse.exe"}:
        return "service_to_shell"
    if child in LOLBINS and parent in SHELLS:
        return "script_to_lolbin"
    return "other"


WAZUH_MAPPING = {
    "T1110.003": "password_spray", "T1621": "mfa_push", "T1114.003": "inbox_rule",
    "T1204.002": "file_detection", "T1059.001": "suspicious_process",
    "T1218.005": "suspicious_process", "T1218.011": "suspicious_process",
    "T1003.001": "credential_access", "T1562.001": "defense_evasion", "T1490": "inhibit_recovery",
}


def wazuh_alert(raw):
    """Project selected fields from a Wazuh manager alerts.json row."""
    if not isinstance(raw, dict):
        raise ValueError("Expected a Wazuh alert object")
    rule = object_value(raw.get("rule"))
    data = object_value(raw.get("data"))
    level = rule.get("level")
    severity = "unknown"
    if type(level) is int and 0 <= level <= 16:
        severity = "high" if level >= 12 else "medium" if level >= 7 else "low"
    techniques = object_value(rule.get("mitre")).get("id")
    if not isinstance(techniques, list):
        techniques = []
    # Map only unambiguous rule tags. Valid-account tags alone do not imply travel.
    candidates = {WAZUH_MAPPING[t] for t in techniques[:25] if isinstance(t, str) and t in WAZUH_MAPPING}
    category = next(iter(candidates)) if len(candidates) == 1 else "unknown"
    syscheck = object_value(raw.get("syscheck"))
    eventdata = object_value(object_value(data.get("win")).get("eventdata"))
    return normalize({"id": raw.get("id"), "category": category, "severity": severity,
                      "process_chain": process_chain(eventdata.get("parentImage"), eventdata.get("image")),
                      "ips": [data.get("srcip"), data.get("dstip")],
                      "hashes": [data.get("sha256"), data.get("sha1"), data.get("md5"),
                                 syscheck.get("sha256_after"), syscheck.get("sha1_after"),
                                 syscheck.get("md5_after")]}, source="wazuh_rule_mapping")


def wazuh_docker_alerts(context, container, limit):
    if not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value) for value in (context, container)):
        raise ValueError("Invalid Docker context or container name")
    if not 1 <= limit <= 50:
        raise ValueError("Wazuh alert limit must be between 1 and 50")
    try:
        result = subprocess.run(
            ["docker", "--context", context, "exec", container, "tail", "-n", str(limit),
             "/var/ossec/logs/alerts/alerts.json"],
            capture_output=True, check=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError("Could not read alerts from the Wazuh Docker manager") from None
    for line in result.stdout.splitlines():
        if len(line) > 128_000:
            raise ValueError("Wazuh alert exceeds the size limit")
        if line.strip():
            yield wazuh_alert(json.loads(line))
