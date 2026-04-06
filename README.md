# OSINT Recon Tool

被动基础设施侦察工具。输入一个域名，自动分析其 DNS 结构、CDN 归属、子域名、暴露路径，并输出一份自包含的 HTML 报告。

灵感来自 [btc.day CDN 暴露案例](https://x.com/mork1e)——通过追踪公开的基础设施信息，一层一层拆开目标的部署结构。

---

## 功能

| 模块 | 做什么 |
|------|--------|
| DNS | 解析 A/AAAA/MX/NS/TXT 记录，追踪 CNAME 链 |
| CDN 识别 | 通过 CNAME 和 HTTP 响应头识别 Cloudflare / Fastly / CloudFront / Akamai 等 |
| 证书透明度 | 查询 crt.sh，发现历史证书中的子域名和 SAN |
| 路径模糊测试 | 异步枚举 60+ 高价值路径，过滤 SPA 误报 |
| WHOIS | 注册商、注册时间、名称服务器 |
| HTML 报告 | 暗色主题，自包含，可离线查看 |

---

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 完整侦察（含路径模糊测试）
python cli.py example.com

# 跳过模糊测试（更快）
python cli.py example.com --no-fuzz

# 指定报告输出路径
python cli.py example.com -o report.html
```

报告会保存为 `<domain>_report.html`，直接用浏览器打开即可。

---

## 项目结构

```
osint/
├── cli.py                  # 入口，串联所有模块，输出进度和报告
├── requirements.txt
├── recon/
│   ├── dns_module.py       # DNS 解析 + CNAME 链 + CDN 提示
│   ├── cdn_module.py       # HTTP 头指纹 + CDN 直连 URL 构造
│   ├── cert_module.py      # crt.sh API + TLS 直连 SAN 提取（双路后备）
│   ├── fuzz_module.py      # 异步路径枚举 + SPA catch-all 过滤
│   └── whois_module.py     # WHOIS 查询
└── report/
    ├── template.html.j2    # Jinja2 暗色 HTML 模板
    └── renderer.py         # 数据 → HTML 渲染
```

---

## 每个模块单独使用

```python
from recon import dns_module, cdn_module, cert_module, fuzz_module

# DNS
result = dns_module.run("target.com")
# → { a_records, cname_chain, cdn_hint, mx_records, ... }

# CDN 识别（可传入 DNS 结果复用）
result = cdn_module.run("target.com", dns_result=dns_result)
# → { cdn_detected, detection_method, key_headers, fastly_direct, ... }

# 证书透明度
result = cert_module.run("target.com")
# → { total_certs, subdomains, wildcards, issuers, tls_direct, ... }

# 路径模糊测试
result = fuzz_module.run("https://target.com")
# → { paths_tested, findings: [{ path, url, status, content_type }, ...] }
```

---

## 报告截面示例

- **Summary Cards** — CDN、IP 数量、子域名数量、暴露路径数量
- **Alerts** — 高亮 Fastly 直连 URL、CloudFront bucket、暴露文件
- **DNS Records** — 完整记录表 + CNAME 链可视化
- **CDN & Infrastructure** — 识别结果 + 关键响应头
- **Path Discovery** — 发现的路径列表（含状态码、大小、类型）
- **Certificate Transparency** — 子域名列表 + 通配符 + CA 信息
- **WHOIS** — 注册商、有效期、名称服务器

---

## 注意事项

- 仅收集公开信息，不发起任何主动攻击行为
- 路径模糊测试会向目标发送 HTTP 请求，请确保你有权限测试目标
- 建议在测试前了解目标所在地区的相关法律法规

---

## 依赖

```
dnspython    # DNS 解析
httpx        # 异步 HTTP 客户端
jinja2       # HTML 模板渲染
rich         # 终端进度显示
python-whois # WHOIS 查询
```
