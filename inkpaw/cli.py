import argparse
import sys
import requests

from . import audit, build, validation
from . import policy as settings

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="构建并校验 Inkpaw Route 配置（Shadowrocket 格式）")
    validation_modes = parser.add_mutually_exclusive_group()
    validation_modes.add_argument(
        "--validate-config",
        metavar="PATH",
        help="只读校验指定配置，不访问网络或写文件",
    )
    validation_modes.add_argument(
        "--validate-monitored-sources",
        action="store_true",
        help="只读下载并严格校验关键在线源，不读写缓存",
    )
    parser.add_argument("--output", default=str(settings.DEFAULT_OUTPUT_PATH), help="生成配置输出路径")
    parser.add_argument("--cache-dir", default=str(settings.DEFAULT_CACHE_DIR), help="规则缓存目录")
    parser.add_argument("--backup-dir", default=str(settings.DEFAULT_BACKUP_DIR), help="生成配置备份目录")
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="不生成时间戳备份（CI 可依赖 Git 历史）",
    )
    parser.add_argument(
        "--openai-generated",
        default=None,
        help="OpenAI 合并 provider 审计文件路径",
    )
    validation_modes.add_argument("--audit-config", metavar="PATH", help="只读验收实际分流场景")
    parser.add_argument("--report", help="与配置一起发布来源状态 JSON")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.audit_config:
            results = audit.audit_config(validation.read_text_strict(args.audit_config))
            print(f"分流场景验收通过: {len(results)} 项")
        elif args.validate_config:
            build.validate_config_file(args.validate_config)
        elif args.validate_monitored_sources:
            build.validate_monitored_sources()
        else:
            build.build_config(
                output_path=args.output,
                cache_dir=args.cache_dir,
                backup_dir=None if args.no_backup else args.backup_dir,
                openai_generated_path=args.openai_generated,
                report_path=args.report,
            )
    except (OSError, requests.RequestException, settings.RuleValidationError) as exc:
        print(f"严重错误: {exc}", file=sys.stderr)
        return 1
    return 0
