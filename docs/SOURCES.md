# 来源与迁移范围

原项目 `gitblackcat23/BCshadowrocket-rules-GPTsplittunnel`，本地基线提交 `f5b1e5194e53fdefb69f102bf6200b4e18e8764f`。原代码、测试及规则中经验证的约束迁入独立模块，原 Git 历史没有迁移、没有推送或改动。

| 来源 | 用途 | 更新方式 |
| --- | --- | --- |
| [Johnshall](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) | 基础直连/代理/去广告规则 | 每日下载，仅采用规则区块 |
| [blackmatrix7 OpenAI](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Shadowrocket/OpenAI) | OpenAI 域名补充 | 每日，敏感类型白名单与范围校验 |
| [MetaCubeX OpenAI](https://github.com/MetaCubeX/meta-rules-dat/blob/sing/geo/geosite/openai.json) | OpenAI 域名补充 | 每日，严格解析 JSON 与已知正则 |
| [blackmatrix7](https://github.com/blackmatrix7/ios_rule_script) | 29 个国内服务列表 | 每日，各来源独立校验与缓存 |
| [Public Suffix List](https://publicsuffix.org/) | 阻止公共后缀级误匹配 | publicsuffixlist 固定版本 |
| [Net.Coffee](https://ip.net.coffee/claude/site.html) | Claude 39 条兼容规则 | 原项目已审阅快照，数量及 SHA-256 固定 |
| [Anthropic 代理文档](https://code.claude.com/docs/en/corporate-proxy) | Claude 安装/运行依赖 | 已审阅本地补充，不日更扩大 |
| [OpenAI 网络说明](https://help.openai.com/en/articles/9247338) | OpenAI 兼容域名 | 沿用已审阅快照 |
| [fmz200](https://github.com/fmz200/wool_scripts)、[blackmatrix7](https://github.com/blackmatrix7/ios_rule_script)、[AWAvenue](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) | 懂球帝广告定位依据 | 本地固定两条接口及一个图片目标 |
| [闲鱼官网](https://www.goofish.com/) | 补齐现有闲鱼列表缺少的主站 | 2026-09-08 核实，精准后缀 DIRECT |

每次真实采用的来源 URL、模式及内容 SHA-256 见根目录 `build-status.json`。所有在线源故障都参与同次更新预警；单独“手动检查全部上游来源”只做连通及格式检查，不据此关闭降级预警。

没有继续携带原项目已经不用的 VPSDance、v2fly、旧 Copilot/Claude 缓存或时间戳备份。保留当前有效的 32 份原始源缓存，以及一份 OpenAI 合并审计缓存。

历史兼容例外并不等于这些流量全部归 AI 服务所有。用户明确要求本次保留效果；未来清理应先按应用实测依赖，再单独调整策略与验收。
