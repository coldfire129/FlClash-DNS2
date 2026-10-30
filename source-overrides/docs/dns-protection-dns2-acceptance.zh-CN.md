# DNS2 修复候选与 Windows 验收要求

版本：`0.9.2-dns2+2026103002`。

**本包是已整合全部 DNS2 改动的完整源码和验证记录，无需应用补丁；当前尚未生成 Windows 客户端安装包。Windows 原生构建、GUI 启动、SCM/Helper/WFP 运行以及实体机防泄漏验收仍未执行。不能把 Linux 测试或 Windows 目标编译检查记为这些项目通过。**

## 已有证据与修复边界

用户提供的最新 DNS1 日志显示：配置已接受、Core enabled=true、Guard 报告 bound=true；最后一份受保护配置的 111 条 DNS 查询全部失败，四项探针全部超时。日志只能把故障定位到解析链路，不能证明是某个公共 DNS 地址、物理路由或 WFP 条件导致。DNS2 尚未证实已解决该 Windows 实体机的最终断网原因。

本轮增量修改，没有移动现有模块或修改 Mihomo 子模块代码：

| 修改 | 具体行为 |
| --- | --- |
| Guard 前校验 | 新增 `dnsProtectionValidate`，使用最终配置验证具体节点及 DNS/TUN 字段。无效名称不再先装配新的 Guard。既有受保护会话不自动释放。 |
| Guard 内验证加密引导 | 新增 `dnsProtectionPreflight`。向已配置的 IPv4 HTTPS 引导地址发送真正的 DNS wire-format POST；检查证书、HTTP 状态、媒体类型、DNS 问题关联及 RCODE，拒绝重定向和明文回退。失败保留阻断，必须显式停止防护恢复网络。 |
| 连通性决定就绪 | 只有配置、进程、Guard 与四条 UDP/TCP DNS 探测均一致才显示就绪。SERVFAIL、REFUSED、伪造/截断/不关联的响应均失败，超时是未知。 |
| 运行时重检 | 定期重检，使用单调计时；按 Core PID、配置序号、Guard 会话和 TUN LUID 使旧样本失效。检查结果不等于完整防泄漏证明。 |
| 停止与恢复 | 取消启动期间的旧配置请求，防止迟到的引导结果重新应用配置或启动监听。Helper 的 Guard 装配与释放在现有 CoreService 内串行；重启应用后可通过当前 Helper 会话查询并释放继承的 Guard。 |
| 多个加密 DNS | 复用原有列表编辑器设置多个加密上游/引导地址，每类最多 8 项。保留既有地址，不擅自替换服务商，不增加系统或 UDP/TCP 明文 DNS 回退。 |
| Helper 日志 | 明确创建 SYSTEM 所有的目录；只修复可信 Administrators 所有的旧目录，继续拒绝不可信所有者和重解析点；暴露日志 Windows 错误码，后续写入成功才解除当前写入错误。此修复尚待真实 SYSTEM 服务验证。 |
| 诊断准确性 | 记录每个引导地址的实际响应阶段；保留 DP_* 原因、DNS RCODE 失败、错误类别及可提取的 OS 码。未观测到实际上游时不推断它；Core 失联仍可导出本地日志，并区分最新状态与上次手动检查。 |

## Windows 原生构建

需要 Windows x64、64 位 PowerShell、Visual Studio 2022 的 C++ 桌面开发组件及 Windows SDK、Flutter 3.47.6、Go 1.27.1、Rust 1.99.1、Git。Flutter 插件符号链接需 Windows 开发者模式或相应权限。构建入口验证工具版本和固定 CA 哈希；源码包已含 CA，Git 检出缺失时从固定版本地址获取并验证哈希。

完整解压源码后，在根目录运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tool\build_dns_windows.ps1
```

入口依次执行依赖安装、代码及本地化生成、分析、Go/Rust/Flutter 测试，再调用原有 `setup.dart windows --targets zip --env pre`，由 Flutter/Visual Studio 原生生成 Runner 和插件，由原有流程计算 Core 哈希、编入 Helper 并打包。禁止混用 DNS1 的 EXE、Helper、manifest 或 AOT。

原始 Flutter 输出位于 `build/windows/x64/runner/Release/`，打包 ZIP 位于 `dist/`，构建脚本收集到 `delivery-dns2/`，包含 `build-logs/`、SHA256 和 `native-build-result.json`。构建失败不会标记成功；即使构建成功，GUI、Helper/WFP、抓包和权威出口字段仍保持 `not_performed`。

`.github/workflows/dns-protection-windows.yaml` 可在专用 GitHub 仓库手动运行 Windows 托管构建。当前工作未推送到用户的其他无关仓库，也没有运行该工作流。

## GUI、Helper/WFP 与实体机验收

需要可访问的专用 Windows 测试机或自托管 Windows Runner，并具备管理员权限、交互式桌面、可用 IPv4 网络、一个已经确认可用的静态代理节点；双栈项目还需要实际可用 IPv6。GitHub Windows 构建通过不能替代用户物理网络上的验收。

先退出原客户端并备份数据。仅启动本次测试进程，记录 PID，不按进程名批量结束程序。停止测试或切换版本前，先点击“停止防护并恢复网络”。除非明确列为故障注入项目，不停止 BFE、系统防火墙或其他服务。

| 项目 | 执行与通过条件 | 必须保留的证据 |
| --- | --- | --- |
| 原生构建来源 | `native-build-result.json` 成功，包中 Runner/Core/Helper/manifest 一致 | Windows 构建日志、源码清单、ZIP 和二进制 SHA256 |
| 实际启动 | Windows 正常模式启动完整包；确认界面版本、进程 PID、无 DLL/AOT 启动错误 | 截图、启动时间、Windows 版本、相关应用错误事件 |
| 普通代理/TUN 基线 | 防护关闭，普通代理及 TUN 分别访问同一国内/国外 HTTPS 网站成功 | A_OFF/B_TUN 快照、节点协议、服务器地址类型 |
| Helper SCM | 按原有入口安装/更新本包 Helper，批准 UAC；SYSTEM 服务运行，路径/协议/Core 哈希匹配 | 服务状态及进程对应关系、Helper 日志、权限或版本错误 |
| 日志权限 | SYSTEM 所有且仅 SYSTEM/Administrators 可写；旧管理员所有目录按预期修复；不可信所有者与重解析点拒绝 | `Get-Acl` 的所有者/权限及日志；`diagnosticError=false`。不得通过放开所有人权限凑通过 |
| 无效节点 | 开启前使用不存在的节点名，应在新 Guard 装配前拒绝；不能显示就绪 | `DP_NO_PROXY`、前后 Guard 状态、普通网络是否被改变 |
| 引导 DNS 故障 | 已确认不可达的 HTTPS 引导或错误证书，必须报具体失败且不回退明文；已有 Guard 保持限制 | `bootstrap_preflight` 的目标/HTTP/错误码、抓包及恢复结果 |
| 正常受保护 DNS | 使用本机实际可达的加密引导与有效节点，四项 UDP/TCP 探针可用且 RCODE 为 0/3，网页可用 | C_ON 导出日志、最新控制状态、手动检查时间、正向访问结果 |
| 物理出口 | 所有实际外联网卡抓包，测试窗口内没有本应被接管的出站 53/853；证明 DNS 正常解析而非完全断网 | 全部物理网卡 PCAPNG、接口清单、时间、请求方向/目的地址分析 |
| IPv6 | 有 IPv6 基线时检查外部 IPv6 DNS/普通外部 IPv6 受限，IPv4 仍可用，NDP 保留 | IPv6 基线与保护后结果、物理抓包。无 IPv6 基线则记未测 |
| 停止/快速切换 | 在引导查询尚未完成时停止；不得随后重新应用旧防护或重新装配 Guard。正常恢复后 DNS/HTTPS 可用 | 开始/停止时间、迟到回调结果、Guard 释放日志、D_RECOVERED 快照 |
| Core 重启/断网恢复 | Helper 存活时验证限制保持，TUN 重新绑定，旧会话不能释放新 Guard | Core PID/配置序号/会话/LUID 前后记录及抓包 |
| 应用重启后恢复 | 受限时重启界面，再显式恢复；应识别继承 Guard，不能仅凭本地字段为空就报告无 Guard | 新旧会话、Guard 查询/释放日志、网络恢复结果 |
| 外部 DNS 出口 | 暂停浏览器自身安全 DNS后进行外部检测，并与系统抓包交叉验证 | 实际检测结果、时间、预期解析服务商、恢复浏览器设置记录 |

可以继续使用已经交付的 `FlClash-DNS-Test-Kit-v1.zip` 收集 A/B/C/D；以当前实际客户端版本和哈希为准。应用导出包包含客户端/Core 日志；管理员需另收集 `%ProgramData%\FlClashDnsProtection\guard*`。未取得 Helper 日志、物理抓包或外部检测时，相应项目不能标记通过。

仅 TUN 内看到 53 流量可能是正常接管；物理接口看到经指定代理的加密流量及已配置的直连加密引导属于预期路径。浏览器检测不能单独证明整个系统没有泄漏，DNS 服务商位置也不必等于代理出口位置。

## 仍然存在的限制

- 仅支持配置根 `proxies:` 内的具体静态节点；不支持动态 provider 中的独立节点和策略组名称。
- 不支持 IPv6-only 网络/节点。应用自带 DoH/DoQ、非标准端口、其他 VPN、本地名称发现不属于已验证覆盖。
- Helper/BFE 退出后不提供持久阻断保证。不能把动态 WFP 策略称为完整的崩溃后 kill switch。
- 运行时状态及探针是采样证据，不代替物理出口和权威解析验收。
- 引导探测使用当前 Core 的拨号环境，不把 HTTPS 响应成功写成“已证明物理直连出口”。
- 没有证据时，不自动关闭证书验证、防火墙、严格路由或 Guard 来恢复连通性。

## 参考

- [Flutter Windows 构建](https://docs.flutter.dev/platform-integration/windows/building)
- [Windows SetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow)
- [Windows 安全描述符格式](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
- [Mihomo DNS 配置及引导解析](https://wiki.metacubex.one/config/dns/)
