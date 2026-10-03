"""Structured bounty findings — dedup, impact, export."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from terminator.core.memory import load_findings, now, save_findings


@dataclass
class Finding:
    title: str
    severity: str  # critical|high|medium|low|info
    category: str
    asset: str
    method: str
    path: str
    param: str = ""
    payload: str = ""
    note: str = ""
    impact: str = ""
    repro_steps: list[str] = field(default_factory=list)
    request_raw: str = ""
    response_raw: str = ""
    evidence: list[str] = field(default_factory=list)
    chain: list[str] = field(default_factory=list)
    state: str = "confirmed"  # tentative|confirmed|duplicate
    technique: str = ""
    cvss_hint: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            blob = f"{self.category}|{self.path}|{self.param}|{self.technique}"
            self.id = hashlib.sha256(blob.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})


def impact_for(category: str, technique: str = "", proof: str = "") -> str:
    impacts = {
        "sqli": "Database read/write — potential full data breach, auth bypass, or RCE via stacked queries.",
        "xss": "Session hijack, account takeover, actions-as-victim, credential phishing in trusted origin.",
        "ssrf": "Internal network access, cloud metadata theft, pivot to internal admin APIs.",
        "idor": "Cross-account data access — PII, financial records, private messages at scale.",
        "jwt": "Authentication bypass — access admin or other users without valid credentials.",
        "mass_assignment": "Privilege escalation — self-assign admin role or sensitive fields.",
        "redirect": "Phishing / OAuth token theft via trusted-domain redirect.",
        "traversal": "Arbitrary file read — secrets, source, /etc/passwd, app config.",
        "cmdi": "Remote code execution on application server.",
        "ssti": "Template injection — RCE or secret key leakage.",
        "cors": "Cross-origin data theft from authenticated sessions.",
        "auth_bypass": "Unauthenticated access to protected functionality.",
        "webshell": "Remote code execution via uploaded web shell — full server compromise as web user.",
        "info_disclosure": "Sensitive configuration/path disclosure enables targeted follow-up exploits.",
    }
    base = impacts.get(category, "Security control bypass with business impact.")
    if "uid=0" in proof or "uid=0" in proof.lower():
        base = "Root-level command execution — full system compromise."
    elif "uid=" in proof:
        base = impacts.get("webshell", base)
    if "admin" in proof.lower() or "secret" in proof.lower():
        base += " Confirmed access to privileged data."
    return base


def finding_from_probe(
    category: str,
    technique: str,
    asset: str,
    method: str,
    path: str,
    param: str,
    payload: str,
    note: str,
    severity: str,
    output: str = "",
    chain: list[str] | None = None,
) -> Finding:
    repro = [
        f"1. Send {method} to {asset}{path}",
        f"2. Set parameter `{param}` to payload (see below)",
        "3. Observe vulnerable behavior in response",
    ]
    if payload:
        repro.append(f"Payload: {payload[:200]}")
    proof = output[:500]
    return Finding(
        title=f"{category.upper()} — {technique} on {path}",
        severity=severity,
        category=category,
        asset=asset,
        method=method,
        path=path,
        param=param,
        payload=payload[:300],
        note=note,
        impact=impact_for(category, technique, proof),
        repro_steps=repro,
        response_raw=proof,
        evidence=[line for line in output.splitlines() if "vulnerable: True" in line or "signals:" in line][:5],
        chain=chain or [],
        technique=technique,
        state="confirmed",
    )


class FindingStore:
    def __init__(self) -> None:
        self.items: dict[str, Finding] = {}

    def add(self, finding: Finding) -> bool:
        if finding.id in self.items:
            finding.state = "duplicate"
            return False
        self.items[finding.id] = finding
        return True

    def extend_from_legacy(self, legacy: list[dict], asset: str) -> None:
        from terminator.catalog import SEVERITY

        for f in legacy:
            cat = f.get("category", "unknown")
            proof = f.get("proof", "") or ""
            if not proof or proof == f.get("note", ""):
                proof = "\n".join(
                    x for x in (
                        f.get("note", ""),
                        ", ".join(f.get("signals", []) or []),
                        f"payload={f.get('payload', '')[:80]}",
                    ) if x
                )
            finding = finding_from_probe(
                category=cat,
                technique=f.get("technique", ""),
                asset=asset,
                method=f.get("method", "GET"),
                path=f.get("path", ""),
                param=f.get("param", ""),
                payload=f.get("payload", ""),
                note=f.get("note", ""),
                severity=f.get("severity") or SEVERITY.get(cat, "medium"),
                output=proof,
                chain=f.get("chain", []) if isinstance(f.get("chain"), list) else [],
            )
            if not self.add(finding):
                finding.state = "duplicate"

    def sorted(self) -> list[Finding]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(self.items.values(), key=lambda f: (order.get(f.severity, 9), f.category))

    def persist(self, target: str, extra: dict | None = None) -> None:
        data = {
            **load_findings(),
            "target": target,
            "updated": now(),
            "bounty_findings": [f.to_dict() for f in self.sorted()],
        }
        if extra:
            data["bounty"] = extra
        save_findings(data)
