# FlClash DNS2 整合源码

版本：`0.9.2-dns2+2026103002`。

全部 DNS2 改动已合入本工程，直接使用这个完整目录即可，无需与旧版合并或应用补丁。

**本文件是完整源码包。目前尚未生成新的 Windows 可运行客户端，Windows 原生构建、启动、Helper/WFP 运行及实体机防泄漏验收均未执行；不能确认用户实体机断网问题已解决。**

- 原生构建入口：`tool/build_dns_windows.ps1`。
- Windows 构建环境和实体机验收清单：`docs/dns-protection-dns2-acceptance.zh-CN.md`。
- 上一轮源码验证记录：`validation-records/`。228 项 Flutter 测试、Go 测试、48 项 Rust 测试及静态分析已通过；Windows 目标编译检查不代表 Windows 原生运行通过。
- 文件校验：`SOURCE-SHA256SUMS.txt`。

在具备文档所列 Windows 工具链的工程根目录执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tool\build_dns_windows.ps1
```

成功构建后的客户端 ZIP 和构建记录输出至 `delivery-dns2/`。当前整合包没有包含该输出目录；包内原有 `windows/EnableLoopback.exe` 只是上游附带的工具，不是 FlClash 客户端。
