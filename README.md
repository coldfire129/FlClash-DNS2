# FlClash DNS2 Windows client

版本：`0.9.2-dns2+2026103002`。

[Windows 原生构建与客户端下载](https://github.com/coldfire129/FlClash-DNS2/actions/workflows/windows-native.yaml)。从成功运行的 Artifacts 下载完整客户端，包含 `FlClash.exe`、Core、Helper、DLL、data 与构建记录；不能只复制主 EXE。

构建任务自动拉取固定的公开 FlClash/Mihomo 上游版本，将 `source-overrides/` 中已经整合的完整文件写入工程，并使用 `build/source-manifest.json` 校验全部 2,492 个源文件。不需要应用补丁，也不会上传历史诊断包或构建日志作为构建输入。

- FlClash 固定版本：`7fd417fb9a9a277c6a9339a8ac87f907df7c25f7`。
- Mihomo 固定版本：`c5062921054902b25215a6a933e72ccd714c9bfa`。
- 工具链：Flutter 3.47.6、Go 1.27.1、Rust 1.99.1、Windows 原生 C++ 工具链。
- 新增与修改文件已检查；上游测试用示例密钥保持原样，不代表真实用户凭据。

构建通过不代表用户实体机上的 DNS 连通性或防泄漏验收通过，实际状态以产物中的 JSON 和测试记录为准。许可证见 `LICENSE` 及各上游源码中的许可文件。
