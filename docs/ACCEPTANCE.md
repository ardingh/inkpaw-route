# 本地验收记录

2026-09-08，首次发布候选。远端尚未创建；以下不是远端 CI 或手机实测结论。

- 原项目基线：`f5b1e5194e53fdefb69f102bf6200b4e18e8764f`。原仓库没有跟踪文件变化，remote 未改，未推送。
- `python -m unittest discover -s tests -v`：40 项测试在 Python 3.10（CI 版本）和本机默认 Python 上通过，涵盖原有分流、严格解析、源数量漂移、缓存回退、跨策略冲突、事务回滚；新增 CLI、全部来源监控、降级/恢复、状态写入失败全组回退、上游不能改变运行设置。
- 实际在线生成成功：32 个来源全部在线，59850 条有效规则。
- `python -m shadowrocket --audit-config custom_shadowrocket_rules.conf`：73 项通过，覆盖 Apple/CloudKit、中国区、国内应用、AI 登录/内容/通信、Copilot、IPv4/IPv6/ASN、默认路由和历史例外。
- `actionlint v1.7.12`：3 个工作流校验退出码 0。官方发布包的校验和已核对。未全局安装；未运行 shellcheck 集成，工作流 Shell 命令已本地实际执行。
- 配置和生成器 hash 与 build-status.json 一致。场景证据见 [acceptance-results.json](acceptance-results.json)，对应首次发布候选；日更后看当次 Actions 和 build-status.json。

## 原效果比对

旧成品 56187 条，新成品 59850 条。去掉广告规则后，旧规则顺序和策略逐条一致，仅新增 `DOMAIN-SUFFIX,goofish.com,DIRECT` 补齐闲鱼官网。常规广告变化来自本次实时 Johnshall 更新。General、URL Rewrite、MITM 的有效设置与旧成品一致。

## 审查发现与处理

1. 原监控仅覆盖 3 源；现在覆盖全部 32 源，按同次生成和提交结果预警、恢复。
2. 原上游可带入 DNS/重写/MITM 变化；现在由本地模板持有，成品拒绝偏离，包括新增 Script 区块。
3. 闲鱼源遗漏主站；核实官网后补入精准后缀，场景验收通过。
4. 新 CLI 入口曾出现旧测试未覆盖的问题；已修复并新增真实子进程测试。
5. AI 规则含关键词、共享依赖、两条云主机单 IP 与全设备 NTP。用户确认保留全部历史例外，未新增类似范围。
6. 节点、证书由设备持有。原 `Proxy` 行继续使用客户端当前代理；HTTPS 路径拦截需要设备自己的 MITM 证书。

## 交付后核验

新仓库首次 CI、一次实际远端更新、公开订阅下载与远端提交一致性，以及定时工作流存在且启用。08:08 是请求时间，GitHub 不保证准点调度。

手机网络、节点质量、登录风控、iCloud 同步和证书信任需要真实客户端观察。本地规则首次命中测试不能替代网络实测。
