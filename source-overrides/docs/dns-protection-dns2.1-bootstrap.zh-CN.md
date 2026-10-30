# DNS2.1 加密引导兼容性修复

版本：`0.9.2-dns2.1+2026103101`。

DNS2 的引导预检要求连接可达的加密 DNS。仅接受 IP 且以 IP 校验证书，会使只提供域名证书的服务无法使用；不能通过关闭证书验证解决。

DNS2.1 保留旧地址和提供商设置，增量支持在固定 IPv4 HTTPS 地址后明确指定证书域名，复用当前 Mihomo 的 `name-cert-verify` 参数。连接仍使用 URL 内的固定 IP；证书链、有效期和指定域名必须验证通过。预检与 Mihomo DNS 交换采用相同的认证规则，不修改 Mihomo 子模块。

## 配置测试

先点击“停止防护并恢复网络”。在“加密引导 DNS”中按需使用以下候选地址，每行一个列表项：

```text
https://223.5.5.5/dns-query#name-cert-verify=dns.alidns.com
https://223.6.6.6/dns-query#name-cert-verify=dns.alidns.com
```

这是明确选择阿里公共 DNS 作为加密引导；应用不会自动替换既有提供商。业务 DNS 上游和具体代理节点继续使用原设置。以上地址能否从用户实际网络访问，必须本机验证。

仅该证书名称参数可用于引导地址；禁止跳过证书验证、注入出口、依赖系统 DNS 或回退明文。域名 URL 仍不能直接作为 default-nameserver，以遵循当前 Mihomo 的纯 IP 约束。

## 诊断

`bootstrap_preflight` 和状态导出新增 `stage`/`failure_stage`、`errorCategory`/`error_category`、`osError`/`os_error`、`certificateName`/`certificate_name`。

阶段包括配置验证、TCP 连接、TLS 握手、请求发送、HTTP 响应、响应体、DNS 响应验证与完成。底层错误码按实际可提取的 Windows socket 错误记录；不存在时保持未知，不能据此断言网络封锁或代理故障。

仍保留 Guard 内预检、业务 DNS 经固定节点、IPv6 限制、证书验证与显式停止恢复；失败不会宣告防护已就绪。

## 验证范围

新增测试覆盖仅含域名 SAN 的证书、错误域名、不可信证书链、注入拒绝、Mihomo 实际 DNS 交换和 socket 错误保留。Windows CI 显式运行公共提供商的加密引导与 Mihomo DNS 互通检查；测试结果以相应运行日志为准。

这些结果不代替用户实体机的 TUN、网络恢复、物理接口抓包或 DNS 出口验收。

参考：[阿里公共 DNS 配置文档](https://www.alidns.com/knowledge?type=SETTING_DOCS#company_doh)、[DoH 说明](https://help.aliyun.com/zh/dns/dns-over-https)。
