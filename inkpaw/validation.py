import hashlib
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from . import policy as settings

def _decode_utf8(data, source_name):
    try:
        return data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise settings.RuleValidationError(f"{source_name}: 内容不是合法 UTF-8") from exc


def read_text_strict(path, source_name=None):
    path = Path(path)
    return _decode_utf8(path.read_bytes(), source_name or str(path))


def _reject_empty_or_html(content, source_name, content_type=""):
    if not content.strip():
        raise settings.RuleValidationError(f"{source_name}: 内容为空")

    lowered_type = content_type.lower()
    sample = content.lstrip()[:256].lower()
    if "text/html" in lowered_type or sample.startswith("<!doctype html") or sample.startswith("<html"):
        raise settings.RuleValidationError(f"{source_name}: 返回了 HTML，而不是规则文本")


def _section_matches(content):
    return list(re.finditer(r"(?m)^\[([^\]\r\n]+)\][ \t]*\r?$", content))


def _section_body_start(content, section_match):
    """Return the first byte after a section header and its line ending."""
    position = section_match.end()
    if position < len(content) and content[position] == "\n":
        position += 1
    return position


def _single_section(content, section_name, source_name):
    matches = [m for m in _section_matches(content) if m.group(1).strip().lower() == section_name.lower()]
    if len(matches) != 1:
        raise settings.RuleValidationError(f"{source_name}: 需要且只能有一个 [{section_name}]，实际为 {len(matches)} 个")
    return matches[0]


def _check_rule_count_ratio(source_name, rule_count, baseline_count):
    if baseline_count is None:
        return

    lower = baseline_count * settings.MIN_RULE_COUNT_RATIO
    upper = baseline_count * settings.MAX_RULE_COUNT_RATIO
    if rule_count < lower or rule_count > upper:
        raise settings.RuleValidationError(
            f"{source_name}: 有效规则数从 {baseline_count} 变为 {rule_count}，"
            f"超出允许范围 {settings.MIN_RULE_COUNT_RATIO:.0%}～{settings.MAX_RULE_COUNT_RATIO:.0%}"
        )


def provider_rule_lines(content, source_name, allowed_rule_types=None):
    lines = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            raise settings.RuleValidationError(f"{source_name}:{line_number}: provider 列表不应包含配置区块")
        validate_provider_rule(
            line,
            source_name,
            line_number,
            allowed_rule_types=allowed_rule_types,
        )
        lines.append(line)
    return lines


def _validate_domain_target(target, location):
    candidate = target[:-1] if target.endswith(".") else target
    if candidate.startswith("*."):
        candidate = candidate[2:]
    try:
        ascii_candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise settings.RuleValidationError(f"{location}: 域名无法进行 IDNA 编码") from exc
    if not ascii_candidate or len(ascii_candidate) > 253:
        raise settings.RuleValidationError(f"{location}: 域名为空或长度超过 253")
    labels = ascii_candidate.split(".")
    label_pattern = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise settings.RuleValidationError(f"{location}: 域名格式不合法 {target!r}")


def _validate_keyword_or_user_agent(target, location, maximum_length):
    if not target or len(target) > maximum_length or any(ord(character) < 32 for character in target):
        raise settings.RuleValidationError(f"{location}: 匹配目标为空、过长或含控制字符")


def _validate_cidr(target, location, expected_version=None):
    if "/" not in target:
        raise settings.RuleValidationError(f"{location}: CIDR 缺少前缀长度")
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise settings.RuleValidationError(f"{location}: CIDR 格式不合法 {target!r}") from exc
    if expected_version is not None and network.version != expected_version:
        raise settings.RuleValidationError(
            f"{location}: CIDR 地址族应为 IPv{expected_version}，实际为 IPv{network.version}"
        )


def _validate_asn(target, location):
    candidate = target[2:] if target.upper().startswith("AS") else target
    if not candidate.isdigit() or not 0 < int(candidate) <= 4_294_967_295:
        raise settings.RuleValidationError(f"{location}: ASN 格式或范围不合法 {target!r}")


def _validate_port(target, location):
    bounds = target.split("-", 1)
    if any(not bound.isdigit() for bound in bounds):
        raise settings.RuleValidationError(f"{location}: 端口格式不合法 {target!r}")
    ports = [int(bound) for bound in bounds]
    if any(not 1 <= port <= 65_535 for port in ports):
        raise settings.RuleValidationError(f"{location}: 端口超出 1～65535 {target!r}")
    if len(ports) == 2 and ports[0] > ports[1]:
        raise settings.RuleValidationError(f"{location}: 端口范围起点大于终点 {target!r}")


def _validate_policy(policy, location):
    # Tolerate the one existing upstream inline comment without treating it as
    # part of the policy name, while preserving the original line byte-for-byte.
    effective_policy = re.split(r"\s+#", policy, maxsplit=1)[0].strip()
    if (
        not effective_policy
        or effective_policy.lower() == "no-resolve"
        or any(ord(character) < 32 for character in effective_policy)
    ):
        raise settings.RuleValidationError(f"{location}: 策略为空、错位或含控制字符")


def validate_provider_rule(
    line,
    source_name="规则源",
    line_number=None,
    allowed_rule_types=None,
):
    location = f"{source_name}:{line_number}" if line_number is not None else source_name
    parts = [part.strip() for part in line.split(",")]
    if allowed_rule_types is None:
        allowed_rule_types = settings.PROVIDER_RULE_TYPES
    if not parts or parts[0].upper() not in allowed_rule_types:
        rule_type = parts[0] if parts else ""
        raise settings.RuleValidationError(f"{location}: 不支持的规则类型 {rule_type!r}")
    if len(parts) < 2 or not parts[1]:
        raise settings.RuleValidationError(f"{location}: 规则目标为空")

    rule_type = parts[0].upper()
    if rule_type in {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "USER-AGENT",
        "DST-PORT",
    }:
        if len(parts) != 2:
            raise settings.RuleValidationError(f"{location}: {rule_type} 应为两个字段且不能预带策略")
    elif len(parts) not in {2, 3}:
        raise settings.RuleValidationError(f"{location}: {rule_type} 字段数量不合法")
    elif len(parts) == 3 and parts[2].lower() != "no-resolve":
        raise settings.RuleValidationError(f"{location}: 第三个字段只能是 no-resolve")

    target = parts[1]
    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        _validate_domain_target(target, location)
    elif rule_type == "DOMAIN-KEYWORD":
        _validate_keyword_or_user_agent(target, location, 253)
    elif rule_type == "USER-AGENT":
        _validate_keyword_or_user_agent(target, location, 1_024)
    elif rule_type == "IP-CIDR":
        # Preserve compatibility with Johnshall's historical IP-CIDR lines that
        # contain IPv6 prefixes. New OpenAI IPv6 rules use explicit IP-CIDR6.
        _validate_cidr(target, location)
    elif rule_type == "IP-CIDR6":
        _validate_cidr(target, location, 6)
    elif rule_type == "IP-ASN":
        _validate_asn(target, location)
    elif rule_type == "DST-PORT":
        _validate_port(target, location)
    return parts


def validate_routed_rule(line, source_name, line_number, allow_match=False):
    """Validate a complete Shadowrocket rule that already contains a settings."""
    location = f"{source_name}:{line_number}"
    parts = [part.strip() for part in line.split(",")]
    rule_type = parts[0].upper() if parts else ""
    allowed_types = settings.JOHNSHALL_RULE_TYPES if allow_match else settings.GENERATED_RULE_TYPES
    if rule_type not in allowed_types:
        raise settings.RuleValidationError(f"{location}: 未知规则类型 {rule_type!r}")

    if rule_type in {"FINAL", "MATCH"}:
        if len(parts) != 2:
            raise settings.RuleValidationError(f"{location}: {rule_type} 必须只有策略字段")
        _validate_policy(parts[1], location)
        return parts

    if len(parts) < 3 or not parts[1]:
        raise settings.RuleValidationError(f"{location}: 规则目标或策略字段缺失")
    _validate_policy(parts[2], location)

    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        if len(parts) != 3:
            raise settings.RuleValidationError(f"{location}: {rule_type} 字段数量不合法")
        _validate_domain_target(parts[1], location)
    elif rule_type == "DOMAIN-KEYWORD":
        if len(parts) != 3:
            raise settings.RuleValidationError(f"{location}: DOMAIN-KEYWORD 字段数量不合法")
        _validate_keyword_or_user_agent(parts[1], location, 253)
    elif rule_type == "USER-AGENT":
        if len(parts) != 3:
            raise settings.RuleValidationError(f"{location}: USER-AGENT 字段数量不合法")
        _validate_keyword_or_user_agent(parts[1], location, 1_024)
    elif rule_type in {"IP-CIDR", "IP-CIDR6"}:
        if len(parts) not in {3, 4}:
            raise settings.RuleValidationError(f"{location}: {rule_type} 字段数量不合法")
        _validate_cidr(parts[1], location, None if rule_type == "IP-CIDR" else 6)
        if len(parts) == 4 and parts[3].lower() != "no-resolve":
            raise settings.RuleValidationError(f"{location}: {rule_type} 可选字段只能是 no-resolve")
    elif rule_type == "IP-ASN":
        if len(parts) not in {3, 4}:
            raise settings.RuleValidationError(f"{location}: IP-ASN 字段数量不合法")
        _validate_asn(parts[1], location)
        if len(parts) == 4 and parts[3].lower() != "no-resolve":
            raise settings.RuleValidationError(f"{location}: IP-ASN 可选字段只能是 no-resolve")
    elif rule_type == "DST-PORT":
        if len(parts) != 3:
            raise settings.RuleValidationError(f"{location}: DST-PORT 字段数量不合法")
        _validate_port(parts[1], location)
    elif rule_type == "GEOIP":
        if len(parts) != 3 or not re.fullmatch(r"[A-Za-z]{2}", parts[1]):
            raise settings.RuleValidationError(f"{location}: GEOIP 国家代码或字段数量不合法")
    elif rule_type == "RULE-SET":
        parsed_url = urlparse(parts[1])
        if len(parts) != 3 or parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise settings.RuleValidationError(f"{location}: RULE-SET URL 或字段数量不合法")
    return parts


def validate_provider_content(
    content,
    source_name,
    baseline_count=None,
    content_type="",
    allowed_rule_types=None,
):
    _reject_empty_or_html(content, source_name, content_type)
    lines = provider_rule_lines(
        content,
        source_name,
        allowed_rule_types=allowed_rule_types,
    )
    if not lines:
        raise settings.RuleValidationError(f"{source_name}: 没有有效规则")
    canonical_source_name = source_name.removesuffix(" 本地缓存")
    audited_baseline = settings.SOURCE_BASELINE_RULE_COUNTS.get(canonical_source_name)
    _check_rule_count_ratio(
        source_name,
        len(lines),
        audited_baseline,
    )
    if baseline_count is not None and baseline_count != audited_baseline:
        _check_rule_count_ratio(source_name, len(lines), baseline_count)
    return len(lines)


def normalize_provider_rule(
    line,
    source_name="OpenAI 规则",
    allowed_rule_types=None,
):
    """Return a canonical provider rule while preserving matching semantics."""
    parts = validate_provider_rule(
        line,
        source_name,
        allowed_rule_types=allowed_rule_types,
    )
    rule_type = parts[0].upper()
    target = parts[1]

    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        target = target.lower().rstrip(".")
    elif rule_type == "DOMAIN-KEYWORD":
        target = target.lower()
    elif rule_type in {"IP-CIDR", "IP-CIDR6"}:
        target = str(ipaddress.ip_network(target, strict=False))
    elif rule_type == "IP-ASN":
        target = target[2:] if target.upper().startswith("AS") else target
    elif rule_type == "DST-PORT":
        target = "-".join(str(int(bound)) for bound in target.split("-", 1))

    normalized = [rule_type, target]
    if len(parts) == 3:
        normalized.append(parts[2].lower())
    return ",".join(normalized)


def _domain_suffix_scopes_intersect(first, second):
    return (
        first == second
        or first.endswith(f".{second}")
        or second.endswith(f".{first}")
    )


def _dynamic_domain_rule_intersects(
    dynamic_rule_type,
    dynamic_target,
    protected_rule_type,
    protected_target,
):
    if protected_rule_type == "DOMAIN":
        if dynamic_rule_type == "DOMAIN":
            return dynamic_target == protected_target
        return (
            dynamic_target == protected_target
            or protected_target.endswith(f".{dynamic_target}")
        )
    if protected_rule_type == "DOMAIN-SUFFIX":
        if dynamic_rule_type == "DOMAIN":
            return (
                dynamic_target == protected_target
                or dynamic_target.endswith(f".{protected_target}")
            )
        return _domain_suffix_scopes_intersect(
            dynamic_target,
            protected_target,
        )
    return protected_target in dynamic_target


def _validate_openai_dynamic_domain_scope(lines, source_name):
    protected_suffixes = [
        (domain.lower().rstrip("."), "Apple/iCloud DIRECT")
        for domain in settings.apple_domains
    ] + [
        (domain.lower().rstrip("."), "Tonghuashun DIRECT")
        for domain in settings.tonghuashun_domains
    ]
    dongqiudi_keyword = settings.DONGQIUDI_AD_RULE.split(",", 2)[1].lower()
    protected_keywords = [
        (keyword.lower(), "Apple/iCloud DIRECT")
        for keyword in settings.apple_keywords
    ] + [
        (dongqiudi_keyword, "Dongqiudi REJECT")
    ]
    for line in lines:
        rule_type, target = line.split(",", 2)[:2]
        if rule_type not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            continue

        labels = target.split(".")
        if len(labels) < 2:
            raise settings.RuleValidationError(
                f"{source_name}: 动态域名范围过宽或不是公网域名 {line!r}"
            )
        if target.startswith("*."):
            raise settings.RuleValidationError(
                f"{source_name}: OpenAI 动态域名禁止通配符目标 {line!r}"
            )
        if (
            rule_type == "DOMAIN-SUFFIX"
            and settings.PUBLIC_SUFFIX_LIST.is_public(target)
            and line not in settings.OPENAI_APPROVED_PUBLIC_SUFFIX_RULES
        ):
            raise settings.RuleValidationError(
                f"{source_name}: 禁止公共后缀级 OpenAI 分流 {line!r}"
            )

        for protected_suffix, policy_name in protected_suffixes:
            if rule_type == "DOMAIN":
                conflicts = (
                    target == protected_suffix
                    or target.endswith(f".{protected_suffix}")
                )
            else:
                conflicts = _domain_suffix_scopes_intersect(
                    target,
                    protected_suffix,
                )
            if conflicts:
                raise settings.RuleValidationError(
                    f"{source_name}: 动态规则 {line!r} 与受保护的 "
                    f"{policy_name} 范围冲突"
                )

        for protected_keyword, policy_name in protected_keywords:
            if protected_keyword in target or (
                rule_type == "DOMAIN-SUFFIX"
                and protected_keyword.endswith(f".{target}")
            ):
                raise settings.RuleValidationError(
                    f"{source_name}: 动态规则 {line!r} 与受保护的 "
                    f"{policy_name} 关键词冲突"
                )


def local_domestic_rules():
    return local_provider_rule_lines(settings.REPOSITORY_DIR / "rules/domestic/extra.list", "国内本地补充")


def _domestic_direct_domain_scopes(domestic_results):
    scopes = [(line.split(",")[0], line.split(",")[1], "国内本地补充 DIRECT")
              for line in local_domestic_rules()]
    for source_name in settings.domestic_lists:
        try:
            is_online, content = domestic_results[source_name]
        except (KeyError, TypeError, ValueError) as exc:
            raise settings.RuleValidationError(
                f"无法审计本次 {source_name} DIRECT 规则"
            ) from exc
        if content is None:
            raise settings.RuleValidationError(
                f"无法审计本次 {source_name} DIRECT 规则: 内容不可用"
            )

        snapshot_name = source_name if is_online else f"{source_name} 本地缓存"
        for line in provider_rule_lines(content, snapshot_name):
            normalized = normalize_provider_rule(line, snapshot_name)
            rule_type, target = normalized.split(",", 2)[:2]
            if rule_type in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
                scopes.append(
                    (rule_type, target, f"{snapshot_name} DIRECT")
                )
            if rule_type == "DOMAIN-KEYWORD":
                for associated_suffix in settings.DOMESTIC_KEYWORD_ASSOCIATED_SUFFIXES.get(
                    (source_name, target),
                    (),
                ):
                    scopes.append(
                        (
                            "DOMAIN-SUFFIX",
                            associated_suffix,
                            f"{snapshot_name} DIRECT 关键词 {target!r} 的关联域名",
                        )
                    )
    return scopes


def _johnshall_protected_domain_scopes(content):
    rule_match, next_section, _ = _johnshall_rule_block(content, "Johnshall")
    rule_body_start = _section_body_start(content, rule_match)
    scopes = []
    for line_number, raw_line in enumerate(
        content[rule_body_start:next_section.start()].splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = validate_routed_rule(
            line,
            "Johnshall [Rule]",
            line_number,
            allow_match=True,
        )
        rule_type = parts[0].upper()
        if rule_type not in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
            continue
        policy = (
            re.split(r"\s+#", parts[2], maxsplit=1)[0].strip().lower()
            if len(parts) >= 3
            else ""
        )
        if policy != "direct" and not policy.startswith("reject"):
            continue
        target = parts[1].lower().rstrip(".")
        scopes.append((rule_type, target, f"Johnshall {policy.upper()}"))
    return scopes


def _validate_openai_rules_against_scopes(openai_rules, protected_scopes):
    for line in openai_rules:
        normalized = normalize_provider_rule(line, "OpenAI 动态新增规则")
        rule_type, target = normalized.split(",", 2)[:2]
        if rule_type not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            continue
        for protected_rule_type, protected_target, policy_name in protected_scopes:
            if _dynamic_domain_rule_intersects(
                rule_type,
                target,
                protected_rule_type,
                protected_target,
            ):
                raise settings.RuleValidationError(
                    f"OpenAI 规则 {normalized!r} 与本次 {policy_name} 规则冲突"
                )


def validate_openai_domestic_policy_compatibility(openai_rules, domestic_results):
    """Reject intersections with this build's selected domestic snapshots."""
    _validate_openai_rules_against_scopes(
        openai_rules,
        _domestic_direct_domain_scopes(domestic_results),
    )


def _openai_domain_rule_is_covered(candidate, approved_rules):
    candidate_type, candidate_target = candidate.split(",", 2)[:2]
    if candidate_type not in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return True

    for approved in approved_rules:
        approved_type, approved_target = approved.split(",", 2)[:2]
        if approved_type == "DOMAIN":
            if candidate_type == "DOMAIN" and candidate_target == approved_target:
                return True
        elif approved_type == "DOMAIN-SUFFIX":
            if candidate_target == approved_target or candidate_target.endswith(
                f".{approved_target}"
            ):
                return True
        elif approved_type == "DOMAIN-KEYWORD" and approved_target in candidate_target:
            return True
    return False


def _new_dynamic_openai_domain_rules(source_rules, approved_rules):
    normalized_approved = {
        normalize_provider_rule(line, "OpenAI 已审核固定规则")
        for line in approved_rules
    }
    additions = []
    for line in source_rules:
        normalized = normalize_provider_rule(line, "OpenAI 动态来源")
        if not _openai_domain_rule_is_covered(normalized, normalized_approved):
            additions.append(normalized)
    return additions


def _contextual_openai_validator(
    base_validator,
    rule_parser,
    approved_rules,
    protected_scopes,
):
    def validate(content, source_name, baseline_count=None, content_type=""):
        count = base_validator(
            content,
            source_name,
            baseline_count=baseline_count,
            content_type=content_type,
        )
        source_rules = rule_parser(content, source_name)
        additions = _new_dynamic_openai_domain_rules(
            source_rules,
            approved_rules,
        )
        _validate_openai_rules_against_scopes(additions, protected_scopes)
        return count

    return validate


def blackmatrix_openai_rule_lines(content, source_name="OpenAI blackmatrix7"):
    return [
        normalize_provider_rule(line, source_name)
        for line in provider_rule_lines(content, source_name)
    ]


def validate_blackmatrix_openai_content(
    content,
    source_name,
    baseline_count=None,
    content_type="",
):
    count = validate_provider_content(
        content,
        source_name,
        baseline_count=baseline_count,
        content_type=content_type,
    )
    sensitive_types = {
        "DOMAIN-KEYWORD",
        "USER-AGENT",
        "IP-CIDR",
        "IP-CIDR6",
        "IP-ASN",
    }
    normalized_lines = blackmatrix_openai_rule_lines(content, source_name)
    if len(normalized_lines) != len(set(normalized_lines)):
        raise settings.RuleValidationError(f"{source_name}: 规范化后含文本重复项")
    _validate_openai_dynamic_domain_scope(normalized_lines, source_name)

    for normalized in normalized_lines:
        rule_type = normalized.split(",", 1)[0]
        if (
            rule_type in sensitive_types
            and normalized not in settings.OPENAI_APPROVED_BLACKMATRIX_SENSITIVE_RULES
        ):
            raise settings.RuleValidationError(
                f"{source_name}: 出现未经审核的高影响规则 {normalized!r}"
            )
    return count


def _load_json_without_duplicate_keys(content, source_name):
    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise settings.RuleValidationError(f"{source_name}: JSON 含重复键 {key!r}")
            result[key] = value
        return result

    def reject_nonstandard_constant(value):
        raise settings.RuleValidationError(f"{source_name}: JSON 含非标准常量 {value!r}")

    try:
        return json.loads(
            content,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonstandard_constant,
        )
    except settings.RuleValidationError:
        raise
    except json.JSONDecodeError as exc:
        raise settings.RuleValidationError(
            f"{source_name}: JSON 格式不合法（第 {exc.lineno} 行第 {exc.colno} 列）"
        ) from exc
    except (RecursionError, ValueError) as exc:
        raise settings.RuleValidationError(f"{source_name}: JSON 无法安全解析") from exc


def _metacubex_string_values(value, field_name, source_name, rule_number):
    location = f"{source_name}: rules[{rule_number}].{field_name}"
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        raise settings.RuleValidationError(f"{location}: 必须是字符串或字符串数组")

    if not values or any(not isinstance(item, str) for item in values):
        raise settings.RuleValidationError(f"{location}: 必须是非空字符串或字符串数组")
    return values


def metacubex_openai_rule_lines(content, source_name="OpenAI MetaCubeX"):
    _reject_empty_or_html(content, source_name)
    document = _load_json_without_duplicate_keys(content, source_name)
    if not isinstance(document, dict):
        raise settings.RuleValidationError(f"{source_name}: JSON 顶层必须是对象")

    required_fields = {"version", "rules"}
    actual_fields = set(document)
    if actual_fields != required_fields:
        missing = sorted(required_fields - actual_fields)
        unexpected = sorted(actual_fields - required_fields)
        raise settings.RuleValidationError(
            f"{source_name}: JSON 顶层字段异常，缺少={missing}，未知={unexpected}"
        )
    if type(document["version"]) is not int or document["version"] != 2:
        raise settings.RuleValidationError(
            f"{source_name}: 只接受 MetaCubeX geosite JSON version 2"
        )
    if not isinstance(document["rules"], list) or not document["rules"]:
        raise settings.RuleValidationError(f"{source_name}: rules 必须是非空数组")

    field_mapping = (
        ("domain", "DOMAIN"),
        ("domain_suffix", "DOMAIN-SUFFIX"),
        ("domain_keyword", "DOMAIN-KEYWORD"),
    )
    allowed_fields = {field_name for field_name, _ in field_mapping} | {
        "domain_regex"
    }
    lines = []
    for rule_number, rule_group in enumerate(document["rules"]):
        if not isinstance(rule_group, dict) or not rule_group:
            raise settings.RuleValidationError(
                f"{source_name}: rules[{rule_number}] 必须是非空对象"
            )
        unknown_fields = sorted(set(rule_group) - allowed_fields)
        if unknown_fields:
            raise settings.RuleValidationError(
                f"{source_name}: rules[{rule_number}] 含未审核字段 {unknown_fields}"
            )

        for field_name, rule_type in field_mapping:
            if field_name not in rule_group:
                continue
            values = _metacubex_string_values(
                rule_group[field_name],
                field_name,
                source_name,
                rule_number,
            )
            for value in values:
                normalized = normalize_provider_rule(
                    f"{rule_type},{value}",
                    f"{source_name}: rules[{rule_number}].{field_name}",
                )
                if (
                    rule_type == "DOMAIN-KEYWORD"
                    and normalized not in settings.OPENAI_APPROVED_METACUBEX_KEYWORD_RULES
                ):
                    raise settings.RuleValidationError(
                        f"{source_name}: 出现未经审核的高影响规则 {normalized!r}"
                    )
                lines.append(normalized)

        if "domain_regex" in rule_group:
            expressions = _metacubex_string_values(
                rule_group["domain_regex"],
                "domain_regex",
                source_name,
                rule_number,
            )
            for expression in expressions:
                rule = settings.OPENAI_METACUBEX_REGEX_RULES.get(expression)
                if rule is None:
                    raise settings.RuleValidationError(
                        f"{source_name}: rules[{rule_number}] 含未审核正则 "
                        f"{expression!r}"
                    )
                lines.append(
                    normalize_provider_rule(
                        rule,
                        f"{source_name}: rules[{rule_number}].domain_regex",
                    )
                )

    if not lines:
        raise settings.RuleValidationError(f"{source_name}: 没有有效规则")
    if len(lines) != len(set(lines)):
        raise settings.RuleValidationError(f"{source_name}: 转换后含文本重复项")
    _validate_openai_dynamic_domain_scope(lines, source_name)
    return lines


def validate_metacubex_openai_content(
    content,
    source_name,
    baseline_count=None,
    content_type="",
):
    _reject_empty_or_html(content, source_name, content_type)
    lines = metacubex_openai_rule_lines(content, source_name)
    canonical_source_name = source_name.removesuffix(" 本地缓存")
    audited_baseline = settings.SOURCE_BASELINE_RULE_COUNTS.get(canonical_source_name)
    _check_rule_count_ratio(
        source_name,
        len(lines),
        audited_baseline,
    )
    if baseline_count is not None and baseline_count != audited_baseline:
        _check_rule_count_ratio(source_name, len(lines), baseline_count)
    return len(lines)


def local_provider_rule_lines(path, source_name, allowed_rule_types=None):
    content = read_text_strict(path, source_name)
    validate_provider_content(
        content,
        source_name,
        allowed_rule_types=allowed_rule_types,
    )
    return [
        normalize_provider_rule(
            line,
            source_name,
            allowed_rule_types=allowed_rule_types,
        )
        for line in provider_rule_lines(
            content,
            source_name,
            allowed_rule_types=allowed_rule_types,
        )
    ]


def local_openai_rule_lines(path, source_name):
    return local_provider_rule_lines(path, source_name)


def _pinned_rule_digest(lines):
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_pinned_claude_rules(path, source_name, expected_count, expected_digest):
    lines = local_provider_rule_lines(
        path,
        source_name,
        allowed_rule_types=settings.PINNED_PROVIDER_RULE_TYPES,
    )
    if len(lines) != expected_count:
        raise settings.RuleValidationError(
            f"{source_name}: 规则数量为 {len(lines)}，预期 {expected_count}"
        )
    if len(lines) != len(set(lines)):
        raise settings.RuleValidationError(f"{source_name}: 含文本重复项")

    digest = _pinned_rule_digest(lines)
    if digest != expected_digest:
        raise settings.RuleValidationError(
            f"{source_name}: 固定内容摘要不匹配，实际 sha256={digest}"
        )
    return lines


def build_claude_rule_groups():
    if settings.claude_node != settings.openai_node:
        raise settings.RuleValidationError(
            "SCCR2685 含 Sentry、Statsig、Intercom、Datadog 等 OpenAI 共享规则；"
            "Claude 与 OpenAI 节点不一致时会破坏受保护分流"
        )

    primary_rules = _load_pinned_claude_rules(
        settings.CLAUDE_SCCR2685_PATH,
        "Claude SCCR2685 固定主规则",
        settings.CLAUDE_SCCR2685_RULE_COUNT,
        settings.CLAUDE_SCCR2685_SHA256,
    )
    legacy_rules = _load_pinned_claude_rules(
        settings.CLAUDE_LEGACY_EXTRA_PATH,
        "Claude 原有兼容补充",
        settings.CLAUDE_LEGACY_EXTRA_RULE_COUNT,
        settings.CLAUDE_LEGACY_EXTRA_SHA256,
    )
    official_rules = [
        normalize_provider_rule(line, "Claude 官方条件补充")
        for line in settings.CLAUDE_OFFICIAL_EXTRA_RULES
    ]

    combined = primary_rules + legacy_rules + official_rules
    if len(combined) != len(set(combined)):
        raise settings.RuleValidationError("Claude SCCR2685、原有兼容与官方条件补充含文本重复项")

    priority_types = {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "USER-AGENT",
    }
    network_types = {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
    primary_priority = [
        line for line in primary_rules if line.split(",", 1)[0] in priority_types
    ]
    primary_network = [
        line for line in primary_rules if line.split(",", 1)[0] in network_types
    ]
    primary_ntp = [
        line for line in primary_rules if line.split(",", 1)[0] == "DST-PORT"
    ]
    if len(primary_priority) + len(primary_network) + len(primary_ntp) != len(primary_rules):
        raise settings.RuleValidationError("Claude SCCR2685 出现未分组的规则类型")
    if primary_ntp != ["DST-PORT,123"]:
        raise settings.RuleValidationError("Claude SCCR2685 NTP 兜底不是唯一的 DST-PORT,123")
    if any(line.split(",", 1)[0] not in priority_types for line in legacy_rules):
        raise settings.RuleValidationError("Claude 原有兼容补充只能包含域名或 User-Agent 规则")
    if any(line.split(",", 1)[0] != "DOMAIN" for line in official_rules):
        raise settings.RuleValidationError("Claude 官方条件补充只能包含精确域名")

    print(
        "-> Claude 固定规则已校验: "
        f"SCCR2685={len(primary_rules)}, legacy={len(legacy_rules)}, "
        f"official-extra={len(official_rules)}, merged={len(combined)}"
    )
    return {
        "primary_priority": primary_priority,
        "legacy_priority": legacy_rules,
        "official_priority": official_rules,
        "network": primary_network,
        "ntp": primary_ntp,
    }


def merge_openai_rule_lines(*rule_groups):
    merged = set()
    for group in rule_groups:
        for line in group:
            normalized = normalize_provider_rule(line)
            parts = normalized.split(",")
            if parts[0] == "IP-ASN" and parts[1] == "20473":
                continue
            if parts[0] in {"DOMAIN", "DOMAIN-SUFFIX"} and parts[1] == "humb.apple.com":
                continue
            merged.add(normalized)

    type_order = {
        "DOMAIN": 0,
        "DOMAIN-SUFFIX": 1,
        "DOMAIN-KEYWORD": 2,
        "USER-AGENT": 3,
        "IP-CIDR": 4,
        "IP-CIDR6": 5,
        "IP-ASN": 6,
    }
    return sorted(
        merged,
        key=lambda line: (
            type_order.get(line.split(",", 1)[0], 99),
            line.split(",")[1],
            line,
        ),
    )


def validate_merged_openai_rules(lines, baseline_rules):
    rules = set(lines)
    if len(lines) != len(rules):
        raise settings.RuleValidationError("OpenAI 合并规则仍含文本重复项")
    if len(lines) < settings.OPENAI_MIN_MERGED_RULES:
        raise settings.RuleValidationError(
            f"OpenAI 合并规则只有 {len(lines)} 条，低于安全下限 {settings.OPENAI_MIN_MERGED_RULES}"
        )

    missing_required = sorted(settings.OPENAI_REQUIRED_RULES - rules)
    if missing_required:
        raise settings.RuleValidationError(f"OpenAI 合并规则缺少哨兵项: {missing_required}")
    missing_baseline = sorted(set(baseline_rules) - rules)
    if missing_baseline:
        raise settings.RuleValidationError(f"OpenAI 合并规则缩减了固定兼容底座: {missing_baseline}")
    if any(line.startswith("IP-ASN,20473,") or line == "IP-ASN,20473" for line in lines):
        raise settings.RuleValidationError("OpenAI 合并规则禁止包含共享托管 ASN 20473")
    return len(lines)


def render_openai_provider(lines, generated_on):
    return (
        "# Inkpaw Route OpenAI merged provider\n"
        "# Sources: conservative baseline + official domain overlay + "
        "blackmatrix7 + MetaCubeX\n"
        f"# Generated: {generated_on.isoformat()}\n"
        f"# Rule count: {len(lines)}\n\n"
        + "\n".join(lines)
        + "\n"
    )


def _johnshall_rule_block(content, source_name):
    sections = _section_matches(content)
    required_names = ["general", "rule", "url rewrite", "mitm"]
    required_matches = []
    for name in required_names:
        matches = [m for m in sections if m.group(1).strip().lower() == name]
        if len(matches) != 1:
            raise settings.RuleValidationError(f"{source_name}: 需要且只能有一个 [{name}] 区块")
        required_matches.append(matches[0])

    positions = [m.start() for m in required_matches]
    if positions != sorted(positions):
        raise settings.RuleValidationError(f"{source_name}: General/Rule/URL Rewrite/MITM 区块顺序异常")

    rule_match = required_matches[1]
    following_sections = [m for m in sections if m.start() > rule_match.start()]
    if not following_sections:
        raise settings.RuleValidationError(f"{source_name}: [Rule] 后缺少下一个配置区块")
    next_section = min(following_sections, key=lambda m: m.start())
    if next_section.start() != required_matches[2].start():
        raise settings.RuleValidationError(
            f"{source_name}: [Rule] 后的下一个区块必须是 [URL Rewrite]，"
            f"实际为 [{next_section.group(1).strip()}]"
        )
    rule_body_start = _section_body_start(content, rule_match)
    return rule_match, next_section, content[rule_body_start:next_section.start()]


def inject_url_rewrite_rules(content, rules, marker, source_name):
    """Prepend locally audited URL rewrites and remove exact upstream duplicates."""
    rewrite_match = _single_section(content, "URL Rewrite", source_name)
    mitm_match = _single_section(content, "MITM", source_name)
    if rewrite_match.start() > mitm_match.start():
        raise settings.RuleValidationError(f"{source_name}: [URL Rewrite] 必须位于 [MITM] 之前")

    body_start = _section_body_start(content, rewrite_match)
    rewrite_body = content[body_start:mitm_match.start()]
    exact_rules = set(rules)
    filtered_body = "".join(
        raw_line
        for raw_line in rewrite_body.splitlines(keepends=True)
        if raw_line.strip() not in exact_rules
    )
    custom_block = marker + "\n" + "\n".join(rules) + "\n\n"
    return (
        content[:body_start]
        + custom_block
        + filtered_body
        + content[mitm_match.start():]
    )


def prepend_mitm_hostnames(content, hostnames, source_name):
    """Add required MITM hosts to the single hostname line without duplicates."""
    mitm_match = _single_section(content, "MITM", source_name)
    sections = _section_matches(content)
    following_sections = [
        match for match in sections if match.start() > mitm_match.start()
    ]
    body_end = min(
        (match.start() for match in following_sections),
        default=len(content),
    )
    body_start = _section_body_start(content, mitm_match)
    mitm_body = content[body_start:body_end]
    hostname_matches = list(
        re.finditer(r"(?m)^(hostname[ \t]*=[ \t]*)([^\r\n]*)", mitm_body)
    )
    if len(hostname_matches) != 1:
        raise settings.RuleValidationError(
            f"{source_name}: [MITM] 需要且只能有一个 hostname 行，实际为 {len(hostname_matches)} 个"
        )

    hostname_match = hostname_matches[0]
    existing = [
        item.strip()
        for item in hostname_match.group(2).split(",")
        if item.strip()
    ]
    existing_lower = {item.lower() for item in existing}
    additions = [
        hostname for hostname in hostnames if hostname.lower() not in existing_lower
    ]
    combined = additions + existing
    replacement = hostname_match.group(1) + ",".join(combined)
    rewritten_body = (
        mitm_body[:hostname_match.start()]
        + replacement
        + mitm_body[hostname_match.end():]
    )
    return content[:body_start] + rewritten_body + content[body_end:]


def validate_johnshall_content(content, source_name, baseline_count=None, content_type=""):
    _reject_empty_or_html(content, source_name, content_type)
    _, _, rule_block = _johnshall_rule_block(content, source_name)

    active_rules = []
    for line_number, raw_line in enumerate(rule_block.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        validate_routed_rule(line, f"{source_name} [Rule]", line_number, allow_match=True)
        active_rules.append(line)

    if len(active_rules) < settings.MIN_JOHNSHALL_RULES:
        raise settings.RuleValidationError(
            f"{source_name}: [Rule] 只有 {len(active_rules)} 条，低于安全下限 {settings.MIN_JOHNSHALL_RULES}"
        )
    _check_rule_count_ratio(source_name, len(active_rules), baseline_count)

    if len(re.findall(r"(?m)^dns-server[ \t]*=", content)) != 1:
        raise settings.RuleValidationError(f"{source_name}: dns-server 行数量不是 1")
    return len(active_rules)


def attach_policy(line, policy):
    """Insert a policy before optional provider-rule options such as no-resolve."""
    parts = validate_provider_rule(
        line,
        allowed_rule_types=settings.PINNED_PROVIDER_RULE_TYPES,
    )
    if not policy or "," in policy or "\n" in policy or "\r" in policy:
        raise settings.RuleValidationError("策略名称为空或包含非法分隔符")
    return ",".join(parts[:2] + [policy] + parts[2:])


def validate_generated_config(content, source_name="生成配置", min_rule_count=None):
    _reject_empty_or_html(content, source_name)
    min_rule_count = settings.MIN_GENERATED_RULES if min_rule_count is None else min_rule_count

    sections = _section_matches(content)
    required_names = ["general", "rule", "url rewrite", "mitm"]
    required_matches = []
    for name in required_names:
        matches = [m for m in sections if m.group(1).strip().lower() == name]
        if len(matches) != 1:
            raise settings.RuleValidationError(f"{source_name}: 需要且只能有一个 [{name}] 区块")
        required_matches.append(matches[0])
    if [m.start() for m in required_matches] != sorted(m.start() for m in required_matches):
        raise settings.RuleValidationError(f"{source_name}: 配置区块顺序异常")

    rule_match = required_matches[1]
    next_section = required_matches[2]
    rule_block = content[rule_match.end():next_section.start()]
    active_rules = []
    final_indexes = []

    for line_number, raw_line in enumerate(rule_block.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = validate_routed_rule(line, f"{source_name} [Rule]", line_number)
        rule_type = parts[0].upper()
        if rule_type == "RULE-SET":
            raise settings.RuleValidationError(
                f"{source_name} [Rule]:{line_number}: 最终配置禁止运行时 RULE-SET"
            )
        if rule_type == "FINAL":
            final_indexes.append(len(active_rules))
        active_rules.append(line)

    if len(active_rules) < min_rule_count:
        raise settings.RuleValidationError(
            f"{source_name}: 主规则只有 {len(active_rules)} 条，低于安全下限 {min_rule_count}"
        )
    if len(final_indexes) != 1:
        raise settings.RuleValidationError(f"{source_name}: FINAL 数量不是 1")
    if final_indexes[0] != len(active_rules) - 1:
        raise settings.RuleValidationError(f"{source_name}: FINAL 不是 [Rule] 中最后一条有效规则")

    if active_rules.count(settings.DONGQIUDI_AD_RULE) != 1:
        raise settings.RuleValidationError(
            f"{source_name}: 懂球帝域名拦截规则数量不是 1"
        )

    rewrite_match = required_matches[2]
    mitm_match = required_matches[3]
    rewrite_block = content[
        _section_body_start(content, rewrite_match):mitm_match.start()
    ]
    rewrite_rules = [
        line.strip()
        for line in rewrite_block.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    for rewrite_rule in settings.DONGQIUDI_REWRITE_RULES:
        if rewrite_rules.count(rewrite_rule) != 1:
            raise settings.RuleValidationError(
                f"{source_name}: 懂球帝 URL Rewrite 规则数量不是 1: {rewrite_rule}"
            )

    following_sections = [
        match for match in sections if match.start() > mitm_match.start()
    ]
    mitm_end = min(
        (match.start() for match in following_sections),
        default=len(content),
    )
    mitm_block = content[_section_body_start(content, mitm_match):mitm_end]
    hostname_lines = [
        line for line in mitm_block.splitlines()
        if re.match(r"^hostname[ \t]*=", line.strip(), flags=re.IGNORECASE)
    ]
    if len(hostname_lines) != 1:
        raise settings.RuleValidationError(
            f"{source_name}: [MITM] hostname 行数量不是 1"
        )
    mitm_hostnames = [
        hostname.strip().lower()
        for hostname in hostname_lines[0].split("=", 1)[1].split(",")
        if hostname.strip()
    ]
    for hostname in settings.DONGQIUDI_MITM_HOSTNAMES:
        if mitm_hostnames.count(hostname) != 1:
            raise settings.RuleValidationError(
                f"{source_name}: 懂球帝 MITM hostname 数量不是 1: {hostname}"
            )

    required_markers = [
        "# Claude SCCR2685 全家桶 (使用节点:",
        "# Apple & iCloud Services (DIRECT)",
        "# Claude SCCR2685 NTP 兜底 (使用节点:",
        "# Tonghuashun (DIRECT)",
        "# Dongqiudi Ads (REJECT)",
        "# OpenAI (使用节点:",
        "# GitHub Copilot & Codex (使用节点:",
        "# --- Johnshall 去广告与基础代理区块 ---",
        "# --- 国内常用 APP 及服务 (DIRECT) ---",
        "# 兜底规则",
    ]
    marker_positions = []
    for marker in required_markers:
        position = rule_block.find(marker)
        if position == -1:
            raise settings.RuleValidationError(f"{source_name}: 缺少顺序标记 {marker}")
        marker_positions.append(position)
    if marker_positions != sorted(marker_positions):
        raise settings.RuleValidationError(f"{source_name}: 主要规则区块顺序发生变化")

    marker_by_prefix = dict(zip(required_markers, marker_positions))
    claude_groups = build_claude_rule_groups()
    expected_priority = [
        attach_policy(line, settings.claude_node)
        for line in (
            claude_groups["primary_priority"]
            + claude_groups["legacy_priority"]
            + claude_groups["official_priority"]
            + claude_groups["network"]
        )
    ]
    if active_rules[:len(expected_priority)] != expected_priority:
        raise settings.RuleValidationError(
            f"{source_name}: Claude SCCR2685 域名/兼容/IP 规则未完整位于 [Rule] 最前"
        )

    ntp_rule = attach_policy(claude_groups["ntp"][0], settings.claude_node)
    ntp_start = marker_by_prefix["# Claude SCCR2685 NTP 兜底 (使用节点:"]
    tonghuashun_start = marker_by_prefix["# Tonghuashun (DIRECT)"]
    ntp_block_rules = [
        line.strip()
        for line in rule_block[ntp_start:tonghuashun_start].splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if ntp_block_rules != [ntp_rule] or active_rules.count(ntp_rule) != 1:
        raise settings.RuleValidationError(
            f"{source_name}: Claude SCCR2685 NTP 兜底缺失、重复或位置异常"
        )
    # Runtime settings are locally owned. An upstream refresh must never add
    # scripts, change DNS/bypass settings, or widen the approved MITM scope.
    template = read_text_strict(settings.REPOSITORY_DIR / "templates/base.conf")
    if non_rule_settings(content) != non_rule_settings(template):
        raise settings.RuleValidationError(f"{source_name}: 运行设置偏离本地模板")
    return len(active_rules)



def non_rule_settings(content):
    """Canonical active directives outside [Rule], including unknown sections."""
    section = None
    result = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
        if section != "rule":
            result.append(line)
    return result
