# FlClash DNS2 Windows client

版本：`0.9.2-dns2+2026103002`，Windows AMD64。

[完整 Windows 客户端与构建记录](https://github.com/coldfire129/FlClash-DNS2/actions/runs/41076296252/artifacts/12987697648) · [Windows 运行验收记录](https://github.com/coldfire129/FlClash-DNS2/actions/runs/41078124719/artifacts/12987742741) · [完整整合源码](https://github.com/coldfire129/FlClash-DNS2/actions/runs/41078124342/artifacts/12987303633)

下载客户端 Artifact 后，取其中的 `FlClash-0.9.2-dns2-windows-amd64.zip` 并完整解压。目录根部有 `FlClash.exe`；保留 Core、Helper、DLL、manifest.json 和 data，再运行客户端。

客户端 ZIP 共 68,968,730 字节，SHA256：

```text
019f039171242653a2fff628b16dc060ad5505ee7fbd2dbc05015a834f466333
```

## 验证结果

| 项目 | 结果及范围 |
| --- | --- |
| 原生构建 | Windows x64 构建、完整运行文件及 Core 哈希一致性通过 |
| Go | 测试通过，诊断日志临时目录用例连续 20 次通过 |
| Helper | 44 项 Windows 测试通过 |
| Flutter | 分析无问题，225 项测试通过 |
| GUI | Windows 虚拟机启动成功并创建窗口 |
| Helper 运行 | SYSTEM SCM 服务、协议、Helper-owned Core 与命名管道身份检查通过 |
| WFP | 无 TUN 条件下，动态子层装配、释放与最终清理通过 |
| 日志与清理 | SYSTEM 所有者/ACL、可信旧管理员所有者修复、Helper 卸载通过 |
| 实体机验收 | TUN DNS 连通性、实际代理出口、物理网卡泄漏、IPv6 双栈及人工界面操作尚未验证 |

原生构建源码提交：`f05ca7510b61e860db93995c1a60fb374d724933`。运行检查脚本提交：`8a7c9aac1707c23382235dd840bbaa2e4ff800f9`。运行报告中的客户端 SHA256 与以上 ZIP 一致。

用户原来的实体机断网原因仍需通过该版本的诊断日志与物理网络测试确认；Windows 虚拟机结果不代替这些项目。打包阶段的 `package-verification.json` 与后续的 `windows-runtime-result.json` 分别记录各自阶段，不能只看前者判断后续验收。

## 源码与复现

完整源码归档包含 2,493 个经 SHA256 校验的文件。归档 SHA256：`86109983ba1df338ee37e3d7f89485965a7a84285d50988ad748114fbb12a916`。

仓库构建任务拉取固定公开 FlClash/Mihomo 上游，将 `source-overrides/` 的完整文件写入原工程，并按 `build/source-manifest.json` 校验所有输入。增量功能保留原有模块，不修改 Mihomo 子模块；无需应用补丁。构建输入不含历史诊断包或用户订阅。

- FlClash：`7fd417fb9a9a277c6a9339a8ac87f907df7c25f7`。
- Mihomo：`c5062921054902b25215a6a933e72ccd714c9bfa`。
- 工具链：Flutter 3.47.6、Go 1.27.1、Rust 1.99.1、Windows 原生 C++ 工具链。
- [原生构建流程](.github/workflows/windows-native.yaml)、[运行验收流程](.github/workflows/windows-runtime.yaml)、[完整源码归档流程](.github/workflows/archive-source.yaml)。

可从 Actions 手动运行原生构建流程；成功后自动进行 Windows 运行检查并归档完整源码。Artifacts 以页面标注的保留期为准；源码清单、完整修改文件与构建流程在仓库中保留。

源代码中的 DNS2 验收文档记录了初始修复设计与当时状态；当前构建及运行证据以上述固定运行记录为准。许可证见 `LICENSE` 和各上游许可文件；公开上游自带的示例密钥属于测试夹具。
