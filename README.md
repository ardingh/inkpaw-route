# Inkpaw Route

个人分流配置，每天北京时间约 08:08 更新。面向已有两条节点的 Shadowrocket 用户，配置不包含节点地址、密码或证书。

## 使用

公开仓库：`ardingh/inkpaw-route`。首次发布验收完成后可订阅：

```text
https://raw.githubusercontent.com/ardingh/inkpaw-route/main/custom_shadowrocket_rules.conf
```

1. 保留现在的配置作为回退，在客户端新建远程配置并填入上面的链接。
2. 确认已有节点的名字准确为 `V3 Static Residential` 和 `V3(vless+vision+reality)`。前者用于 AI 服务，后者用于未匹配流量。
3. 配置仍保留上游的 `Proxy` 策略；它使用客户端选择的代理。请沿用原来的选择。配置不会创建或替换节点。
4. 使用配置规则模式。依次检查 iCloud 备忘录同步、ChatGPT/Claude 登录与对话、Codex/Copilot、同花顺行情，以及国内应用。
5. 懂球帝的两条广告接口通过 URL Rewrite 拦截。只有设备已开启 HTTPS 解密并信任自己的证书时，HTTPS 路径拦截才生效；配置不提供共享证书，也不会自动安装证书。

若新订阅有问题，切回旧配置即可；原 personal 仓库和订阅保持不动。远端单个坏版本可以通过普通 Git revert 后重新生成恢复，不需强制推送或删历史。

## 分流效果

| 流量 | 去向 |
| --- | --- |
| Apple/iCloud（含中国区、CloudKit、apple-dns.net） | DIRECT |
| 同花顺、已纳入国内服务 | DIRECT；保留优先级更高的广告拦截 |
| OpenAI/ChatGPT、Claude、Codex、GitHub Copilot 及已确认依赖 | V3 Static Residential |
| 懂球帝广告图片、两条广告接口 | 精准拦截 |
| 常规广告、国内外基础规则 | 保留原 Johnshall 规则行为 |
| 未匹配流量 | V3(vless+vision+reality) |

已有兼容例外按用户确认保留：`openai`、`claude`、`anthropic`、`datadog`、`sentry`、`sift` 等关键词；若干共享服务后缀、`24.199.123.28/32`、`64.23.132.171/32`，以及全设备目标端口 123。它们可能让其他应用流量也走住宅出口。Apple 时间域名优先 DIRECT。日更不得再扩张 AI 的 IP、ASN 或关键词范围；共享 Vultr ASN 20473 被明确排除。

## 更新与故障

- 全部 32 个在线来源在构建时下载、严格校验并内联，客户端没有运行时 RULE-SET 依赖。
- 每个来源有独立的最后有效缓存；在线源不可用时用缓存，并记录降级。在线与缓存都不可用时停止生成，不发布不完整配置。
- 配置、缓存、OpenAI 审计列表和 `build-status.json` 作为一组写入，普通写入失败会回退。GitHub 只在测试、校验、分流场景验收通过后提交；订阅读到的是完整 Git 版本。
- 预警来自同一次构建的真实结果，覆盖国内服务源。降级或更新失败时新建/更新一条 Issue；全部在线且生成和提交成功后关闭。GitHub 通知能否送达取决于账号的通知设置。
- `templates/base.conf` 固定现有 DNS、绕过、重写和 MITM 设置，在线源不能静默修改这些内容。
- GitHub 的定时运行可能排队或延迟，并非精确闹钟；异常可在 Actions 手动执行“自动更新规则并同步缓存”。[官方调度说明](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)

## 本地维护

Python 3.10 或以上：

```sh
python -m pip install --requirement requirements.txt
python -m unittest discover -s tests -v
python -m shadowrocket --no-backup --report build-status.json
python -m shadowrocket --validate-config custom_shadowrocket_rules.conf
python -m shadowrocket --audit-config custom_shadowrocket_rules.conf
```

只读检查全部在线来源（不使用缓存）：

```sh
python -m shadowrocket --validate-monitored-sources
```

`--output`、`--cache-dir`、`--report` 可指定独立试运行路径。自动更新不产生时间戳备份，由 Git 历史保留成功版本。定时和手动更新串行执行，不强制推送；远端分叉时失败并预警，避免覆盖新提交。

| 目录/模块 | 职责 |
| --- | --- |
| shadowrocket/policy.py | 个人策略、来源地址及变化边界 |
| shadowrocket/validation.py | 格式、数量、跨策略冲突和成品校验 |
| shadowrocket/sources.py | 有界下载、重试、逐源缓存回退 |
| shadowrocket/build.py | 选择来源、构建配置及状态报告 |
| shadowrocket/storage.py | 文件事务和生成器指纹 |
| shadowrocket/audit.py、checks/traffic.json | 可复现的用户场景首次命中验收 |
| rules/、templates/ | 本地审阅的规则和运行设置 |
| backups/rules_cache/ | 当前有效来源快照 |

详见 [来源说明](docs/SOURCES.md) 和 [验收记录](docs/ACCEPTANCE.md)。规则版权和适用条件依各上游项目说明；本项目保留来源标注，不把第三方规则重新声明为统一许可证。
