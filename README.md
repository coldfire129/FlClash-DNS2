# FlClash DNS2.1 Windows client

版本：`0.9.2-dns2.1+2026103102`，Windows AMD64。

[完整 Windows 客户端与构建记录](https://github.com/coldfire129/FlClash-DNS2/actions/runs/41093933852/artifacts/12996680993) · [Windows 运行验收](https://github.com/coldfire129/FlClash-DNS2/actions/runs/41095694604/artifacts/12994983612) · [完整整合源码](https://github.com/coldfire129/FlClash-DNS2/actions/runs/41095694627/artifacts/12996885739)

从客户端 Artifact 中取出 `FlClash-0.9.2-dns2.1-windows-amd64.zip` 并完整解压，运行根目录 `FlClash.exe`。保留 Core、Helper、DLL、manifest.json 与 data；无需应用补丁。

客户端 ZIP 大小 68,975,045 字节，SHA256：

```text
1e23024a8f1cdb49a0fc59e5b1fc32bd3472280d28ff45da75e0c120aa0d6360
```

## 引导兼容性修复

加密引导检测失败会阻止受保护配置生效。DNS2.1 增量支持固定 IPv4 HTTPS 连接与显式域名证书校验，复用现有 Mihomo 的 `name-cert-verify`，继续验证证书链与指定域名，并记录连接阶段及可提取的 socket 错误码。

受保护启动失败时保留启动意图，避免重试落入普通配置流程；不再调用会隐式释放 Guard 的普通启动失败清理路径，显式停止仍释放已装配的 Guard。

先停止旧版防护并退出，再运行完整新包。在“加密引导 DNS”中可以明确选择以下候选配置，每行一个列表项：

```text
https://223.5.5.5/dns-query#name-cert-verify=dns.alidns.com
https://223.6.6.6/dns-query#name-cert-verify=dns.alidns.com
```

这些配置选择阿里公共 DNS 作为加密引导。软件保留既有设置，不会自动替换旧的引导服务商。先保留业务 DNS 上游和具体代理节点，只修改引导以便对比测试。上述参数需要 DNS2.1；不要把运行图标或开关开启视作 DNS 防护已经就绪。

## 验证结果

| 项目 | 结果及范围 |
| --- | --- |
| 完整客户端 | Windows 原生构建通过；4 个主要 AMD64 PE 文件及 Core/manifest 哈希一致 |
| Go | 测试通过；诊断日志目录用例连续 20 次通过 |
| 公共 DNS 互通 | Windows 预检以 dns.alidns.com 验证 223.5.5.5，HTTP 200；Mihomo 实际 DoH 查询 RCODE=0 |
| Helper | 44 项 Windows 测试通过 |
| Flutter | 分析通过（1 项非阻断测试代码风格提示），230 项测试通过 |
| 启动失败路径 | 普通初始化失败、受保护初始化失败、受保护手动启动失败及显式停止回归测试通过 |
| GUI | Windows 虚拟机创建窗口并保持运行 |
| Helper 运行 | SYSTEM SCM 服务、协议、Helper-owned Core 与命名管道身份检查通过 |
| WFP | 无 TUN 条件下，动态子层装配、释放与清理通过 |
| 日志/清理 | SYSTEM 所有者/ACL、可信旧管理员所有者修复与 Helper 卸载通过 |
| 实体机 | 用户 TUN、具体代理节点、物理接口 DNS 泄漏、IPv6 与人工交互尚未验收 |

构建源码及运行检查脚本提交：`7623ee81796b1ed5ba2cba037cc7210df9a0d3ee`。运行记录对应以上客户端 ZIP 哈希。打包阶段与后续运行检查分别记录在 `package-verification.json` 和 `windows-runtime-result.json`。

## 源码与复现

完整源码归档有 2,495 个 SHA256 校验文件，归档 SHA256：`3c4ad2302b40fefa602a937620e31f23d33a48f850a9d5776247760db51af0fd`。

构建任务拉取固定公开上游，将 `source-overrides/` 的完整文件写入原工程，按 `build/source-manifest.json` 逐文件验证。没有移动现有模块或修改 Mihomo 子模块；构建输入不含历史用户诊断包、订阅或密码。

- FlClash：`7fd417fb9a9a277c6a9339a8ac87f907df7c25f7`。
- Mihomo：`c5062921054902b25215a6a933e72ccd714c9bfa`。
- 工具链：Flutter 3.47.6、Go 1.27.1、Rust 1.99.1、Windows 原生 C++ 工具链。
- [原生构建](.github/workflows/windows-native.yaml)、[运行检查](.github/workflows/windows-runtime.yaml)、[源码归档](.github/workflows/archive-source.yaml)。

可手动运行 Actions 原生构建，成功后自动运行 Windows 检查并归档源码。Artifacts 保留期以页面为准；源码输入清单、完整修改文件及构建流程在仓库中保留。源码中的 DNS2 初始验收文档是设计与当时状态快照；当前证据以上述固定运行记录为准。

这些结果不能证明用户原来的实体机断网问题已解决或整个系统没有 DNS 泄漏。许可证见 `LICENSE` 与各上游许可文件，公开上游的示例密钥属于测试夹具。
