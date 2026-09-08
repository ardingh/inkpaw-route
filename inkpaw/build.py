import concurrent.futures
import datetime
import hashlib
import json
import re
from pathlib import Path
import requests

from . import policy as settings
from . import sources
from . import storage
from . import validation

def build_openai_provider(
    cache_dir,
    pending_cache_updates,
    generated_path,
    generated_on,
    johnshall_content,
    domestic_results,
    journal=None,
):
    baseline_rules = validation.local_openai_rule_lines(
        settings.OPENAI_COMPATIBILITY_PATH,
        "OpenAI 固定兼容底座",
    )
    official_rules = validation.local_openai_rule_lines(
        settings.OPENAI_OFFICIAL_PATH,
        "OpenAI 官方兼容层",
    )
    approved_rules = validation.merge_openai_rule_lines(baseline_rules, official_rules)
    domestic_scopes = validation._domestic_direct_domain_scopes(domestic_results)
    # Fixed rules represent the approved pre-migration behavior and currently have
    # no domestic DIRECT intersections. Dynamic additions must also preserve the
    # current Johnshall DIRECT/Reject policies.
    validation._validate_openai_rules_against_scopes(approved_rules, domestic_scopes)
    protected_scopes = domestic_scopes + validation._johnshall_protected_domain_scopes(
        johnshall_content
    )
    blackmatrix_validator = validation._contextual_openai_validator(
        validation.validate_blackmatrix_openai_content,
        validation.blackmatrix_openai_rule_lines,
        approved_rules,
        protected_scopes,
    )
    metacubex_validator = validation._contextual_openai_validator(
        validation.validate_metacubex_openai_content,
        validation.metacubex_openai_rule_lines,
        approved_rules,
        protected_scopes,
    )

    source_results, source_updates = sources.fetch_sources_parallel(
        [
            (
                "blackmatrix",
                settings.openai_blackmatrix_url,
                cache_dir / "OpenAI_blackmatrix7.list",
                "OpenAI blackmatrix7",
                blackmatrix_validator,
            ),
            (
                "metacubex",
                settings.openai_metacubex_url,
                cache_dir / "OpenAI_MetaCubeX.json",
                "OpenAI MetaCubeX",
                metacubex_validator,
            ),
        ],
        journal=journal,
    )
    pending_cache_updates.extend(source_updates)

    blackmatrix_online, blackmatrix_content = source_results["blackmatrix"]
    if blackmatrix_content is None:
        raise settings.RuleValidationError("OpenAI blackmatrix7 在线内容和本地缓存都不可用")
    blackmatrix_rules = validation.blackmatrix_openai_rule_lines(blackmatrix_content)

    metacubex_online, metacubex_content = source_results["metacubex"]
    if metacubex_content is None:
        raise settings.RuleValidationError("OpenAI MetaCubeX 在线内容和本地缓存都不可用")
    metacubex_rules = validation.metacubex_openai_rule_lines(metacubex_content)

    merged_rules = validation.merge_openai_rule_lines(
        baseline_rules,
        official_rules,
        blackmatrix_rules,
        metacubex_rules,
    )
    validation.validate_merged_openai_rules(merged_rules, baseline_rules)
    rendered_provider = validation.render_openai_provider(merged_rules, generated_on)

    pending_cache_updates.append((cache_dir / "OpenAI.list", rendered_provider))
    pending_cache_updates.append((Path(generated_path), rendered_provider))

    digest = hashlib.sha256(("\n".join(merged_rules) + "\n").encode("utf-8")).hexdigest()
    source_modes = ", ".join(
        [
            f"blackmatrix7={'online' if blackmatrix_online else 'cache'}",
            f"MetaCubeX={'online' if metacubex_online else 'cache'}",
        ]
    )
    print(
        "-> OpenAI 合并完成: "
        f"baseline={len(baseline_rules)}, official={len(official_rules)}, "
        f"blackmatrix7={len(blackmatrix_rules)}, "
        f"MetaCubeX={len(metacubex_rules)}, "
        f"merged={len(merged_rules)}, "
        f"sha256={digest}, {source_modes}"
    )
    return merged_rules


def build_config(
    output_path=settings.DEFAULT_OUTPUT_PATH,
    cache_dir=settings.DEFAULT_CACHE_DIR,
    backup_dir=settings.DEFAULT_BACKUP_DIR,
    now=None,
    openai_generated_path=None,
    report_path=None,
):
    output_path = Path(output_path)
    cache_dir = Path(cache_dir)
    backup_dir = Path(backup_dir) if backup_dir is not None else None
    if openai_generated_path is None:
        default_output = settings.REPOSITORY_DIR / settings.DEFAULT_OUTPUT_PATH
        if output_path.resolve() == default_output.resolve():
            openai_generated_path = settings.OPENAI_GENERATED_PATH
        else:
            openai_generated_path = output_path.with_name("OpenAI.generated.list")
    cache_dir.mkdir(parents=True, exist_ok=True)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    pending_cache_updates = []
    journal = []

    print(f"[{now}] 开始构建规则...")

    # 1. 构建硬编码高优先级规则。Claude 域名必须是 [Rule] 的首批有效规则；
    # Apple 仍放在全局 NTP 兜底之前，避免 time.apple.com 被端口规则抢走。
    apple_rules_str = f"# Apple & iCloud Services (DIRECT) - {now.strftime('%Y-%m-%d')}\n"
    apple_rules_str += "".join([f"DOMAIN-SUFFIX,{d},DIRECT\n" for d in settings.apple_domains]) + "\n"
    apple_rules_str += "".join([f"DOMAIN-KEYWORD,{d},DIRECT\n" for d in settings.apple_keywords]) + "\n"

    tonghuashun_rules_str = f"# Tonghuashun (DIRECT) - {now.strftime('%Y-%m-%d')}\n"
    tonghuashun_rules_str += "".join([f"DOMAIN-SUFFIX,{d},DIRECT\n" for d in settings.tonghuashun_domains]) + "\n"

    dongqiudi_rules_str = (
        "# Dongqiudi Ads (REJECT) - 懂球帝去广告\n"
        f"{settings.DONGQIUDI_AD_RULE}\n\n"
    )

    # 2. 构建 Copilot & OpenAI 强制分流
    copilot_rules_str = f"# GitHub Copilot & Codex (使用节点: {settings.openai_node})\n"
    copilot_rules_str += "".join([f"DOMAIN,{d},{settings.openai_node}\n" for d in settings.copilot_domains]) + "\n"

    claude_groups = validation.build_claude_rule_groups()
    claude_rules_str = f"# Claude SCCR2685 全家桶 (使用节点: {settings.claude_node})\n"
    claude_rules_str += "# SCCR2685 主规则（域名与关键词优先）\n"
    for line in claude_groups["primary_priority"]:
        claude_rules_str += f"{validation.attach_policy(line, settings.claude_node)}\n"
    claude_rules_str += "# 原有 Claude 兼容补充（SCCR2685 未逐字包含）\n"
    for line in claude_groups["legacy_priority"]:
        claude_rules_str += f"{validation.attach_policy(line, settings.claude_node)}\n"
    claude_rules_str += "# Anthropic 官方条件补充（npm/bun 安装共享 registry）\n"
    for line in claude_groups["official_priority"]:
        claude_rules_str += f"{validation.attach_policy(line, settings.claude_node)}\n"
    claude_rules_str += "# SCCR2685 Anthropic 自有 IP / ASN 兜底\n"
    for line in claude_groups["network"]:
        claude_rules_str += f"{validation.attach_policy(line, settings.claude_node)}\n"
    claude_rules_str += "\n"

    claude_ntp_rules_str = f"# Claude SCCR2685 NTP 兜底 (使用节点: {settings.claude_node})\n"
    claude_ntp_rules_str += "# 全设备端口规则；置于 Apple 域名直连之后以保护 Apple NTP。\n"
    for line in claude_groups["ntp"]:
        claude_ntp_rules_str += f"{validation.attach_policy(line, settings.claude_node)}\n"
    claude_ntp_rules_str += "\n"

    core_results, core_updates = sources.fetch_sources_parallel(
        [
            (
                "johnshall",
                settings.johnshall_url,
                cache_dir / "johnshall_latest.conf",
                "Johnshall",
                validation.validate_johnshall_content,
            ),
        ],
        journal=journal,
    )
    pending_cache_updates.extend(core_updates)

    # 3. 处理 Johnshall 基础与去广告规则
    _, j_content = core_results["johnshall"]
    if j_content is None:
        raise settings.RuleValidationError("Johnshall 在线内容和本地缓存都不可用，保留现有配置")

    rule_match, next_section, _ = validation._johnshall_rule_block(j_content, "Johnshall")
    rule_body_start = validation._section_body_start(j_content, rule_match)
    j_rules_raw = j_content[rule_body_start:next_section.start()]
    template = validation.read_text_strict(settings.REPOSITORY_DIR / "templates/base.conf")
    template_rule = validation._single_section(template, "Rule", "本地模板")
    template_rewrite = validation._single_section(template, "URL Rewrite", "本地模板")
    before_rules = template[:validation._section_body_start(template, template_rule)]
    after_rules = template[template_rewrite.start():]

    # Remove upstream entries that conflict with the explicit iCloud DIRECT policy above.
    upstream_apple_conflicts = {
        "DOMAIN-SUFFIX,cvws.apple-dns.net,Proxy",
        "DOMAIN-SUFFIX,news.apple-dns.net,Proxy",
        "DOMAIN-SUFFIX,gateway.fe.apple-dns.net,Proxy",
        "DOMAIN-SUFFIX,icloud-cdn.icloud.com.akadns.net,Proxy",
        "DOMAIN-SUFFIX,www-cdn.icloud.com.akadns.net,Proxy",
        "DOMAIN-SUFFIX,metrics.icloud.com,Reject",
    }
    locally_owned_rules = {
        settings.DONGQIUDI_AD_RULE.upper(),
    }
    j_rules_clean = "\n".join([
        line for line in j_rules_raw.splitlines()
        if line.strip().split(",", 1)[0].upper() not in {"FINAL", "MATCH"}
        and line.strip() not in upstream_apple_conflicts
        and line.strip().upper() not in locally_owned_rules
    ])

    # 4. 并行获取并内联国内直连规则，客户端只执行构建时校验过的内容。
    domestic_rules_str = "\n# --- 国内常用 APP 及服务 (DIRECT) ---\n"
    for line in validation.local_domestic_rules():
        domestic_rules_str += validation.attach_policy(line, "DIRECT") + "\n"
    domestic_results, domestic_updates = sources.fetch_sources_parallel(
        [
            (
                name,
                url,
                cache_dir / f"{name}.list",
                name,
                validation.validate_provider_content,
            )
            for name, url in settings.domestic_lists.items()
        ],
        journal=journal,
    )
    pending_cache_updates.extend(domestic_updates)

    for name in settings.domestic_lists:
        is_dom_online, dom_content = domestic_results[name]
        if dom_content is None:
            raise settings.RuleValidationError(f"{name} 在线内容和本地缓存都不可用，保留现有配置")
        source_name = name if is_dom_online else f"{name} 本地缓存"
        mode = "在线校验快照" if is_dom_online else "本地缓存快照"
        domestic_rules_str += f"# {name} ({mode}内联)\n"
        for line in validation.provider_rule_lines(dom_content, source_name):
            domestic_rules_str += f"{validation.attach_policy(line, 'DIRECT')}\n"

    # OpenAI candidate validation now has the same-build Johnshall and domestic
    # snapshots available. A conflicting online candidate falls back to its own LKG;
    # a recovered online source can replace an older conflicting LKG without self-lock.
    openai_rules_str = f"# OpenAI (使用节点: {settings.openai_node})\n"
    openai_rules = build_openai_provider(
        cache_dir,
        pending_cache_updates,
        openai_generated_path,
        now.date(),
        j_content,
        domestic_results,
        journal=journal,
    )
    for line in openai_rules:
        openai_rules_str += f"{validation.attach_policy(line, settings.openai_node)}\n"
    openai_rules_str += "\n"

    # Final defense-in-depth check across the fully merged OpenAI rules and every
    # selected domestic DIRECT snapshot.
    validation.validate_openai_domestic_policy_compatibility(openai_rules, domestic_results)

    # 5. 核心严格拼装顺序。SCCR2685 域名/IP 位于所有通用规则之前；
    # 全局 NTP 在 Apple 域名后，避免改变受保护的 Apple 时间服务策略。
    final_rules = (
        claude_rules_str
        + apple_rules_str
        + claude_ntp_rules_str
        + tonghuashun_rules_str
        + dongqiudi_rules_str
        + openai_rules_str
        + copilot_rules_str
        + "\n# --- Johnshall 去广告与基础代理区块 ---\n"
        + j_rules_clean
        + domestic_rules_str
        + f"\n\n# 兜底规则\nFINAL,{settings.default_node}\n"
    )

    generator_metadata = (
        "# Inkpaw Route generated configuration\n"
        f"# Generator: inkpaw sha256={storage.generator_source_sha256()}\n"
    )
    new_content = generator_metadata + before_rules + final_rules + after_rules
    validation.validate_generated_config(new_content)

    # 缓存、审计产物、可选备份和正式配置一次性发布；任一替换失败即回滚全部。
    publication = list(pending_cache_updates)
    previous_content = None
    if output_path.exists():
        previous_content = validation.read_text_strict(output_path, str(output_path))
    semantic_change = (
        previous_content is None
        or storage.semantic_config_fingerprint(previous_content)
        != storage.semantic_config_fingerprint(new_content)
    )

    if backup_dir is not None and semantic_change:
        backup_path = backup_dir / f"inkpaw-route_{now.strftime('%Y%m%d_%H%M%S')}.conf"
        publication.append((backup_path, new_content))
    elif backup_dir is not None:
        print("-> 主规则语义未变化，跳过时间戳备份")
    publication.append((output_path, new_content))
    if report_path is not None:
        report = {
            "schema_version": 1,
            "generated_at": now.isoformat(),
            "status": "degraded" if any(item["mode"] != "online" for item in journal) else "healthy",
            "generator_sha256": storage.generator_source_sha256(),
            "config_sha256": hashlib.sha256(new_content.encode("utf-8")).hexdigest(),
            "sources": journal,
        }
        publication.append((Path(report_path), json.dumps(report, ensure_ascii=False, indent=2) + "\n"))
    storage.transactional_write_text(publication)

    print(f"[{datetime.datetime.now()}] 规则已成功重构并生成！")
    return new_content


def validate_config_file(path):
    content = validation.read_text_strict(path)
    rule_count = validation.validate_generated_config(content, str(path))
    print(f"配置校验通过: {path} ({rule_count} 条有效规则)")
    return rule_count


def validate_monitored_sources():
    """Strictly validate live critical sources without reading or writing caches."""
    specifications = [
        (
            "Johnshall",
            settings.johnshall_url,
            validation.validate_johnshall_content,
        ),
        (
            "OpenAI blackmatrix7",
            settings.openai_blackmatrix_url,
            validation.validate_blackmatrix_openai_content,
        ),
        (
            "OpenAI MetaCubeX",
            settings.openai_metacubex_url,
            validation.validate_metacubex_openai_content,
        ),
    ]

    specifications.extend(
        (name, url, validation.validate_provider_content)
        for name, url in settings.domestic_lists.items()
    )

    def validate_one(source_name, url, validator):
        response_bytes, content_type = sources._download_source(url, source_name)
        content = validation._decode_utf8(response_bytes, source_name)
        return validator(
            content,
            source_name,
            content_type=content_type,
        )

    worker_count = min(settings.MAX_DOWNLOAD_WORKERS, len(specifications))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            source_name: executor.submit(
                validate_one,
                source_name,
                url,
                validator,
            )
            for source_name, url, validator in specifications
        }

        results = {}
        failures = []
        for source_name, _, _ in specifications:
            try:
                results[source_name] = futures[source_name].result()
            except (OSError, requests.RequestException, settings.RuleValidationError) as exc:
                failures.append(f"{source_name}: {exc}")

    if failures:
        raise settings.RuleValidationError(
            "关键在线规则源严格校验失败：\n- " + "\n- ".join(failures)
        )

    for source_name, rule_count in results.items():
        print(f"在线规则源校验通过: {source_name} ({rule_count} 条有效规则)")
    return results
