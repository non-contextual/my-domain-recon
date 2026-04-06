# OSINT Recon Tool

被动基础设施侦察工具。输入一个域名，自动分析其 DNS 结构、CDN 归属、技术栈、邮件安全配置、子域名、暴露路径，并输出自包含的 HTML + Markdown 报告。

灵感来自 [btc.day CDN 暴露案例](https://x.com/mork1e)——通过追踪公开的基础设施信息，一层一层拆开目标的部署结构。

---

## 功能

| 模块 | 做什么 |
|------|--------|
| DNS | 解析 A/AAAA/MX/NS/TXT 记录，追踪 CNAME 链 |
| CDN 识别 | 通过 CNAME 和 HTTP 响应头识别 Cloudflare / Fastly / CloudFront / Akamai 等 |
| 技术指纹 | 通过 HTTP 头、HTML 内容、Cookie 识别框架 / CMS / 语言（WordPress、Next.js、Django 等） |
| 邮件安全 | 查询 SPF / DMARC / DKIM，评级 `strong` / `partial` / `missing` |
| 证书透明度 | 查询 crt.sh，发现历史证书中的子域名和 SAN |
| 路径模糊测试 | 异步枚举 80+ 高价值路径，过滤 SPA 误报，区分 200（暴露）和 403（受限） |
| `.DS_Store` 解析 | 发现可读的 `.DS_Store` 后自动解析二进制，提取目录文件列表 |
| Shodan | 可选：查询开放端口、服务 banner、CVE 漏洞（需设置 `SHODAN_API_KEY`） |
| WHOIS | 注册商、注册时间、名称服务器 |
| Diff 对比 | 与历史快照对比，发现新增路径、子域名、IP 和技术栈变化 |
| 批量扫描 | 从文件读取域名列表，逐个扫描，输出汇总表格 |
| HTML + MD 报告 | 暗色主题，自包含，可离线查看 |

---

## 快速开始

```bash
pip install -r requirements.txt

# 完整侦察
python cli.py example.com

# 跳过路径模糊测试（更快）
python cli.py example.com --no-fuzz

# 指定报告输出路径
python cli.py example.com -o report.html

# 保存 JSON 快照（用于后续 diff）
python cli.py example.com --snapshot

# 与旧快照对比
python cli.py example.com --diff example_com_20260101_snapshot.json

# 批量扫描
python cli.py -f domains.txt

# 启用 Shodan（需要 API Key）
export SHODAN_API_KEY=your_key_here
python cli.py example.com
```

---

## 项目结构

```
osint/
├── cli.py                  # 入口：串联所有模块、进度展示、批量扫描、diff、快照
├── requirements.txt
├── recon/
│   ├── dns_module.py       # DNS 解析 + CNAME 链 + CDN 提示 + SPF/DMARC/DKIM
│   ├── cdn_module.py       # HTTP 头指纹 + CDN 直连 URL 构造
│   ├── cert_module.py      # crt.sh API + TLS 直连 SAN 提取（双路后备）
│   ├── fuzz_module.py      # 异步路径枚举 + SPA 过滤 + .DS_Store 解析
│   ├── tech_module.py      # 技术指纹识别（headers / HTML / cookies）
│   ├── shodan_module.py    # Shodan API 集成（可选）
│   └── whois_module.py     # WHOIS 查询
└── report/
    ├── template.html.j2    # Jinja2 暗色 HTML 模板
    └── renderer.py         # 数据 → HTML + Markdown 渲染
```

---

## 模块 API

```python
from recon import dns_module, cdn_module, cert_module, fuzz_module, tech_module, shodan_module

# DNS + 邮件安全
result = dns_module.run("target.com")
# → { a_records, cname_chain, cdn_hint, email_security: {spf, dmarc, dkim, score}, ... }

# CDN 识别
result = cdn_module.run("target.com", dns_result=dns_result)
# → { cdn_detected, detection_method, key_headers, fastly_direct, ... }

# 技术指纹
result = tech_module.run("target.com")
# → { techs: ["Nginx", "WordPress"], generator: "WordPress 6.4", details: {...} }

# 证书透明度
result = cert_module.run("target.com")
# → { total_certs, subdomains, wildcards, issuers, ... }

# 路径模糊测试（含 .DS_Store 自动解析）
result = fuzz_module.run("https://target.com")
# → { paths_tested, findings: [{ path, url, status, content_type, ds_store_files? }, ...] }

# Shodan（需要 SHODAN_API_KEY 环境变量）
result = shodan_module.run(["1.2.3.4", "5.6.7.8"])
# → { enabled, all_ports, all_vulns, results: { ip: { ports, services, vulns, geo } } }
```

---

## 报告截面

- **Summary Cards** — CDN、IP 数量、技术栈、邮件安全评级、暴露路径、子域名
- **Alerts** — Shodan CVE、邮件安全缺失、暴露文件、Fastly/CloudFront 直连 URL
- **Email Security** — SPF / DMARC / DKIM 逐项状态 + 综合评级
- **CDN & Infrastructure** — 识别结果 + 关键响应头
- **Technology Stack** — 技术列表 + 检测来源（headers / HTML / cookies）
- **Shodan Intelligence** — 开放端口、服务 banner、CVE、地理信息（可选）
- **Path Discovery** — 分为 Exposed（200）/ Restricted（403）/ Other 三段
- **Certificate Transparency** — 子域名列表 + 通配符 + CA 信息
- **WHOIS** — 注册商、有效期、名称服务器
- **Change Detection** — 与历史快照的 diff 结果（可选）

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
