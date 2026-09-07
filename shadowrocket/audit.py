"""Deterministic first-match checks for explicitly supplied traffic attributes.

This does not resolve DNS or emulate device routing, bypass-tun, or certificates.
Missing IP/ASN/country/user-agent attributes do not match those rule types.
"""
import fnmatch
import ipaddress
import json
import re
from pathlib import Path

from . import policy, validation


def parse_rules(content):
    _, _, block = validation._johnshall_rule_block(content, "分流验收")
    return [tuple(part.strip() for part in line.split(","))
            for raw in block.splitlines()
            if (line := raw.strip()) and not line.startswith("#")]


def first_match(rules, traffic):
    host = traffic.get("host", "").lower().rstrip(".")
    address = ipaddress.ip_address(traffic["ip"]) if traffic.get("ip") else None
    for parts in rules:
        kind, target = parts[:2]
        kind = kind.upper()
        matched = False
        if kind == "FINAL":
            return target, ",".join(parts)
        if kind == "DOMAIN":
            matched = host == target.lower().rstrip(".")
        elif kind == "DOMAIN-SUFFIX":
            suffix = target.lower().rstrip(".")
            matched = host == suffix or host.endswith("." + suffix)
        elif kind == "DOMAIN-KEYWORD":
            matched = bool(host) and target.lower() in host
        elif kind in {"IP-CIDR", "IP-CIDR6"} and address is not None:
            matched = address in ipaddress.ip_network(target, strict=False)
        elif kind == "IP-ASN":
            matched = str(traffic.get("asn", "")) == target.removeprefix("AS")
        elif kind == "DST-PORT" and traffic.get("port") is not None:
            bounds = [int(item) for item in target.split("-")]
            matched = bounds[0] <= traffic["port"] <= bounds[-1]
        elif kind == "GEOIP":
            matched = target.upper() == traffic.get("country", "").upper()
        elif kind == "USER-AGENT" and traffic.get("user_agent"):
            matched = fnmatch.fnmatchcase(traffic["user_agent"], target)
        if matched:
            return re.split(r"\s+#", parts[2], maxsplit=1)[0], ",".join(parts)
    raise policy.RuleValidationError("分流验收未找到 FINAL")


def audit_config(content, scenarios=None):
    validation.validate_generated_config(content)
    if scenarios is None:
        scenarios = json.loads((policy.REPOSITORY_DIR / "checks/traffic.json").read_text())
    rules = parse_rules(content)
    results = []
    for case in scenarios:
        actual, matched_rule = first_match(rules, case["traffic"])
        expected = case["expected"]
        if actual.upper() != expected.upper():
            raise policy.RuleValidationError(
                f"分流验收失败 {case['name']}: 预期 {expected}，实际 {actual}；{matched_rule}"
            )
        results.append({"name": case["name"], "traffic": case["traffic"],
                        "policy": actual, "matched_rule": matched_rule})
    return results
