from pathlib import Path
from publicsuffixlist import PublicSuffixList


default_node = "V3(vless+vision+reality)"


openai_node = "V3 Static Residential"


claude_node = "V3 Static Residential"


DEFAULT_CACHE_DIR = Path("backups/rules_cache")


DEFAULT_BACKUP_DIR = Path("backups")


DEFAULT_OUTPUT_PATH = Path("custom_shadowrocket_rules.conf")


REPOSITORY_DIR = Path(__file__).resolve().parent.parent


OPENAI_RULES_DIR = REPOSITORY_DIR / "rules/openai"


OPENAI_COMPATIBILITY_PATH = OPENAI_RULES_DIR / "compatibility-baseline.list"


OPENAI_OFFICIAL_PATH = OPENAI_RULES_DIR / "official-extra.list"


OPENAI_GENERATED_PATH = OPENAI_RULES_DIR / "generated.list"


CLAUDE_RULES_DIR = REPOSITORY_DIR / "rules/claude"


CLAUDE_SCCR2685_PATH = CLAUDE_RULES_DIR / "sccr2685.list"


CLAUDE_LEGACY_EXTRA_PATH = CLAUDE_RULES_DIR / "legacy-extra.list"


CLAUDE_SCCR2685_RULE_COUNT = 39


CLAUDE_LEGACY_EXTRA_RULE_COUNT = 15


CLAUDE_SCCR2685_SHA256 = "d36acf549e26fba491436a8b42c1c98de1db0f669f70ff2c8a368eb5efc1f817"


CLAUDE_LEGACY_EXTRA_SHA256 = "032059abf3b92ba23925d9e398482df5fd890079aea27538c9e4e0153952f3f0"


CLAUDE_OFFICIAL_EXTRA_RULES = (
    # Anthropic 官方说明 npm/bun 安装需要访问该共享 registry；用户于
    # 2026-08-05 明确批准纳入 Claude 固定出口。
    "DOMAIN,registry.npmjs.org",
)


SOURCE_TIMEOUT_SECONDS = 12


SOURCE_CONNECT_TIMEOUT_SECONDS = 5


SOURCE_DOWNLOAD_ATTEMPTS = 3


SOURCE_RETRY_BACKOFF_SECONDS = 0.25


SOURCE_DOWNLOAD_CHUNK_SIZE = 64 * 1024


MAX_SOURCE_BYTES = 16 * 1024 * 1024


MAX_DOWNLOAD_WORKERS = 8


ALLOWED_SOURCE_HOSTS = {
    "johnshall.github.io",
    "raw.githubusercontent.com",
}


MIN_RULE_COUNT_RATIO = 0.5


MAX_RULE_COUNT_RATIO = 2.0


MIN_JOHNSHALL_RULES = 10_000


MIN_GENERATED_RULES = 10_000


SOURCE_BASELINE_RULE_COUNTS = {
    "OpenAI blackmatrix7": 35,
    "OpenAI MetaCubeX": 23,
    "WeChat": 33,
    "WeType": 1,
    "Zhihu": 7,
    "Weibo": 4,
    "DouBan": 3,
    "ByteDance": 371,
    "DouYin": 13,
    "BiliBili": 127,
    "XiaoHongShu": 4,
    "NetEaseMusic": 30,
    "Himalaya": 18,
    "JingDong": 249,
    "Pinduoduo": 3,
    "XianYu": 16,
    "SMZDM": 9,
    "MeiTuan": 7,
    "CaiNiao": 9,
    "AliPay": 21,
    "CMB": 38,
    "ICBC": 58,
    "CCB": 18,
    "EastMoney": 33,
    "DiDi": 25,
    "XieCheng": 29,
    "12306": 15,
    "Baidu": 251,
    "ChinaMobile": 36,
    "ChinaTelecom": 83,
    "115": 10,
}


PROVIDER_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "USER-AGENT",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
}


PINNED_PROVIDER_RULE_TYPES = PROVIDER_RULE_TYPES | {"DST-PORT"}


GENERATED_RULE_TYPES = PINNED_PROVIDER_RULE_TYPES | {
    "GEOIP",
    "RULE-SET",
    "FINAL",
}


JOHNSHALL_RULE_TYPES = PROVIDER_RULE_TYPES | {
    "GEOIP",
    "RULE-SET",
    "FINAL",
    "MATCH",
}


OPENAI_MIN_MERGED_RULES = 65


OPENAI_METACUBEX_REGEX_RULES = {
    r"^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$": (
        "DOMAIN-KEYWORD,chatgpt-async-webps-prod-"
    ),
}


OPENAI_APPROVED_BLACKMATRIX_SENSITIVE_RULES = {
    "DOMAIN-KEYWORD,openai",
    "IP-CIDR,24.199.123.28/32,no-resolve",
    "IP-CIDR,64.23.132.171/32,no-resolve",
    # The upstream list currently includes shared Vultr ASN 20473. It is safe to
    # accept into the validated raw snapshot only because merge_openai_rule_lines()
    # always removes it before policy attachment.
    "IP-ASN,20473,no-resolve",
}


OPENAI_APPROVED_METACUBEX_KEYWORD_RULES = {
    "DOMAIN-KEYWORD,openai",
}


PUBLIC_SUFFIX_LIST = PublicSuffixList()


OPENAI_APPROVED_PUBLIC_SUFFIX_RULES = {
    # The PSL private section records these entries under OpenAI. Routing their
    # complete suffixes is intentional and both are already in the fixed baseline.
    "DOMAIN-SUFFIX,chatgpt.site",
    "DOMAIN-SUFFIX,oaiusercontent.com",
}


DOMESTIC_KEYWORD_ASSOCIATED_SUFFIXES = {
    # The upstream Weibo provider expresses most service roots explicitly, but its
    # broad `weibo` keyword also owns active hosts below sina.com (for example
    # weibo.sina.com). Keep that relationship explicit for cross-policy auditing.
    ("Weibo", "weibo"): ("sina.com",),
}


OPENAI_REQUIRED_RULES = {
    "DOMAIN-SUFFIX,chat.com",
    "DOMAIN-SUFFIX,chatgpt.com",
    "DOMAIN-SUFFIX,chatgpt.livekit.cloud",
    "DOMAIN-SUFFIX,host.livekit.cloud",
    "DOMAIN-SUFFIX,oaistatic.com",
    "DOMAIN-SUFFIX,oaistatsig.com",
    "DOMAIN-SUFFIX,oaiusercontent.com",
    "DOMAIN-SUFFIX,openai.com",
    "DOMAIN-SUFFIX,sora.com",
    "DOMAIN-SUFFIX,turn.livekit.cloud",
    "DOMAIN,openai.qualtrics.com",
    "DOMAIN,ws.chatgpt.com",
    "IP-CIDR,199.47.142.0/23,no-resolve",
    "IP-CIDR6,2604:f20::/32,no-resolve",
    "IP-ASN,401518,no-resolve",
}


class RuleValidationError(ValueError):
    """Raised when downloaded or generated rule content is unsafe to use."""


apple_domains = [
    "apple.com", "apple.cn", "apple-cloudkit.com", "apple-livephotoskit.com",
    # Apple added this suffix to its iCloud network requirements in July 2026.
    "apple-dns.net",
    "icloud.com", "icloud.com.cn", "icloud-content.com", "me.com",
    "files.apple.com", "ws.icloud.com", "com.apple.ubiquity.bulletin", "com.apple.photos",
    "identity.apple.com", "gs.apple.com", "albert.apple.com", "gdmf.apple.com",
    "setup.icloud.com", "configuration.apple.com", "itunes.com", "mzstatic.com",
    "cdn-apple.com", "aaplimg.com", "static.ips.apple.com", "apps.apple.com",
    "p30-buy.itunes.apple.com", "books.itunes.apple.com", "secure.store.apple.com",
    "news-assets.apple.com", "streaming.apple.com", "music.apple.com", "tv.apple.com",
    "search.itunes.apple.com", "push.apple.com", "1-courier.push.apple.com",
    "2-courier.push.apple.com", "3-courier.push.apple.com", "4-courier.push.apple.com",
    "5-courier.push.apple.com", "captive.apple.com", "deviceenrollment.apple.com",
    "deviceservices-external.apple.com", "iprofiles.apple.com", "sq-device.apple.com",
    "tbsc.apple.com", "time.apple.com", "time-ios.apple.com", "time-macos.apple.com",
    "gsa.apple.com", "iadsdk.apple.com", "metrics.apple.com", "wallet.apple.com",
    "weather-data.apple.com", "api.weather.com", "siri.apple.com", "locationd.apple.com",
    "icloud-api.apple.com", "mask.icloud.com", "mask-h2.icloud.com", "gateway.icloud.com",
    # Explicit iCloud diagnostics and newer Apple hosts to keep Shadowrocket routing direct.
    "gc.apple.com", "icloud.apple.com", "probe.icloud.com", "pong.icloud.com",
    "mask-api.icloud.com", "metrics.icloud.com",
    # iCloud China/CNAME paths are required for reliable Notes and CloudKit sync.
    "apzones.com", "apple-icloud.cn", "appleicloud.cn", "icloud-apple.cn",
    "icloud.cn", "icloud.net.cn", "icloudapple.cn",
    "www-cdn.icloud.com.akadns.net",
]


apple_keywords = [
    "icloud.com.akadns.net",
]


tonghuashun_domains = [
    "10jqka.com.cn", "hexin.cn", "data.10jqka.com.cn", "t.10jqka.com.cn",
    "news.10jqka.com.cn", "q.10jqka.com.cn", "basic.10jqka.com.cn", "moni.10jqka.com.cn",
    "upass.10jqka.com.cn", "user.10jqka.com.cn", "search.10jqka.com.cn", "5188.money.10jqka.com.cn",
]


copilot_domains = [
    "api.githubcopilot.com",
    "copilot-proxy.githubusercontent.com",
    "copilot-telemetry.githubusercontent.com",
    "origin-tracker.githubusercontent.com",
]


DONGQIUDI_AD_RULE = "DOMAIN-KEYWORD,apimg.qunliao.info,REJECT"


DONGQIUDI_REWRITE_RULE = r"^https?:\/\/ap\.dongdianqiu\.com\/plat\/v4 reject"


DONGQIUDI_LEGACY_REWRITE_RULE = r"^https?:\/\/ap\.dongqiudi\.com\/plat\/v4 reject"


DONGQIUDI_MITM_HOSTNAME = "ap.dongdianqiu.com"


DONGQIUDI_LEGACY_MITM_HOSTNAME = "ap.dongqiudi.com"


DONGQIUDI_REWRITE_RULES = (
    DONGQIUDI_REWRITE_RULE,
    DONGQIUDI_LEGACY_REWRITE_RULE,
)


DONGQIUDI_MITM_HOSTNAMES = (
    DONGQIUDI_MITM_HOSTNAME,
    DONGQIUDI_LEGACY_MITM_HOSTNAME,
)


domestic_lists = {
    "WeChat": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/WeChat/WeChat.list",
    "WeType": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/WeType/WeType.list",
    "Zhihu": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Zhihu/Zhihu.list",
    "Weibo": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Weibo/Weibo.list",
    "DouBan": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/DouBan/DouBan.list",
    "ByteDance": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ByteDance/ByteDance.list",
    "DouYin": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/DouYin/DouYin.list",
    "BiliBili": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/BiliBili/BiliBili.list",
    "XiaoHongShu": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/XiaoHongShu/XiaoHongShu.list",
    "NetEaseMusic": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/NetEaseMusic/NetEaseMusic.list",
    "Himalaya": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Himalaya/Himalaya.list",
    "JingDong": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/JingDong/JingDong.list",
    "Pinduoduo": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Pinduoduo/Pinduoduo.list",
    "XianYu": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/XianYu/XianYu.list",
    "SMZDM": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/SMZDM/SMZDM.list",
    "MeiTuan": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/MeiTuan/MeiTuan.list",
    "CaiNiao": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/CaiNiao/CaiNiao.list",
    "AliPay": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/AliPay/AliPay.list",
    "CMB": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/CMB/CMB.list",
    "ICBC": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ICBC/ICBC.list",
    "CCB": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/CCB/CCB.list",
    "EastMoney": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/EastMoney/EastMoney.list",
    "DiDi": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/DiDi/DiDi.list",
    "XieCheng": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/XieCheng/XieCheng.list",
    "12306": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/12306/12306.list",
    "Baidu": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Baidu/Baidu.list",
    "ChinaMobile": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ChinaMobile/ChinaMobile.list",
    "ChinaTelecom": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ChinaTelecom/ChinaTelecom.list",
    "115": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/115/115.list",
}


openai_blackmatrix_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list"


openai_metacubex_url = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.json"


johnshall_url = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip_ad.conf"
