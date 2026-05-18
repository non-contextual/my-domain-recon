"""
风险量化分析脚本 — 用于撰写漏洞披露报告

目标:
    从 ftp_data.json 元数据中统计暴露面规模, 不读取任何文件内容,
    不在输出里包含任何学号/姓名样本(只输出聚合数字)。

对应报告里需要的关键数字:
    - 总端口数 / 允许匿名登录的端口数
    - 含「学生提交」关键词的目录数
    - 文件名匹配学号格式(8+ 位连续数字)的文件数
    - 文件扩展名分布(PDF/DOC/RAR/ZIP/MP4 等)
    - 总暴露文件数 / 总暴露字节数
    - Serv-U 版本(从 banner 提取)
"""

import json
import re
from collections import Counter

DATA_FILE = "ftp_data.json"

# 学生提交目录的路径关键词 — 命中即视为「学生隐私敏感目录」
STUDENT_SUBMIT_KEYWORDS = [
    "上传", "upload",
    "学生", "作业", "提交",
    "实验报告", "课程作业",
    "答辩", "毕设", "毕业设计",
    "期末考试", "试卷",
    "课程设计",
]

# 学号正则 — 国内学校学号一般 8-12 位连续数字
# 严格一点用 8 位以上 (避开年份 2024 这种 4 位)
STUDENT_ID_RE = re.compile(r"\d{8,}")


def parse_listing_line(line: str):
    """解析单行 LIST 输出, 返回 (is_dir, size, name) 或 None"""
    if not line or line[0] not in "d-l":
        return None
    parts = line.split(maxsplit=8)
    if len(parts) < 9:
        return None
    name = parts[8]
    if name in (".", ".."):
        return None
    try:
        size = int(parts[4])
    except ValueError:
        size = 0
    return line.startswith("d"), size, name


def main():
    with open(DATA_FILE, encoding="utf-8") as f:
        data = json.load(f)

    ports = data["ports"]
    errors = data["errors"]

    # ---- 端口层面统计 ----
    total_probed = len(ports) + len(errors)
    anon_allowed = len(ports)
    anon_denied = sum(1 for e in errors if "perm" in e["error"].lower()
                      or "denied" in e["error"].lower()
                      or "530" in e["error"])

    # Serv-U 版本(从任意一个 welcome banner 提取)
    serv_u_version = "unknown"
    for p in ports:
        m = re.search(r"Serv-U FTP Server v[\d.]+", p["welcome"])
        if m:
            serv_u_version = m.group(0)
            break

    # ---- 目录/文件层面统计 ----
    student_submit_dirs = 0       # 学生提交关键词命中的目录数
    student_submit_dir_paths = []  # 命中目录的路径(用于报告抽样, 但需匿名化)
    total_files = 0
    total_bytes = 0
    student_id_filename_count = 0
    ext_counter: Counter = Counter()
    big_files = []  # 单文件 > 100MB 的, 报告里点一下「连大型文件也暴露」

    # 端口里的「学生提交」热区 — 每个端口含多少个学生提交目录
    port_submit_hotspots: Counter = Counter()

    for p in ports:
        port = p["port"]
        for path, lines in p["tree"].items():
            path_lower = path.lower()
            is_submit_path = any(kw.lower() in path_lower for kw in STUDENT_SUBMIT_KEYWORDS)
            if is_submit_path:
                student_submit_dirs += 1
                student_submit_dir_paths.append((port, path))
                port_submit_hotspots[port] += 1

            for line in lines:
                parsed = parse_listing_line(line)
                if not parsed:
                    continue
                is_dir, size, name = parsed
                if is_dir:
                    continue  # 只数文件, 不数子目录(避免和 student_submit_dirs 重复)
                total_files += 1
                total_bytes += size

                # 扩展名
                ext = name.rsplit(".", 1)[-1].lower() if "." in name else "noext"
                if len(ext) > 8:  # 防止把"v1.zip的副本.docx"这种解析坏
                    ext = "other"
                ext_counter[ext] += 1

                # 学号格式文件名
                if STUDENT_ID_RE.search(name):
                    student_id_filename_count += 1

                # 大文件
                if size > 100 * 1024 * 1024:
                    big_files.append((port, name, size))

    # ---- 输出 ----
    print("=" * 60)
    print("暴露面量化结果 (聚合数据, 不含任何个人信息)")
    print("=" * 60)
    print(f"\n[端口层]")
    print(f"  探测端口总数:           {total_probed}")
    print(f"  允许匿名登录:           {anon_allowed}")
    print(f"  明确拒绝匿名(配置正确): {anon_denied}")
    print(f"  Serv-U 版本:            {serv_u_version}")

    print(f"\n[目录层]")
    print(f"  含学生提交关键词目录数: {student_submit_dirs}")
    print(f"  集中暴露 Top 10 端口   (每个端口含多少学生提交目录):")
    for port, n in port_submit_hotspots.most_common(10):
        print(f"    端口 {port}: {n} 个学生提交相关目录")

    print(f"\n[文件层]")
    print(f"  暴露文件总数:           {total_files:,}")
    print(f"  暴露总体积:             {total_bytes / 1024**3:.2f} GB")
    print(f"  文件名含学号格式(8+位): {student_id_filename_count:,}")
    print(f"  其中 > 100 MB 的大文件: {len(big_files)}")

    print(f"\n[扩展名分布 Top 15]")
    for ext, n in ext_counter.most_common(15):
        print(f"    .{ext:<8} {n:>6,}")

    # ---- 把结果导出 JSON, 给报告生成器用 ----
    summary = {
        "total_probed": total_probed,
        "anon_allowed": anon_allowed,
        "anon_denied": anon_denied,
        "serv_u_version": serv_u_version,
        "student_submit_dirs": student_submit_dirs,
        "port_submit_hotspots_top10": port_submit_hotspots.most_common(10),
        "total_files": total_files,
        "total_bytes": total_bytes,
        "student_id_filename_count": student_id_filename_count,
        "big_files_count": len(big_files),
        "ext_distribution_top15": ext_counter.most_common(15),
    }
    with open("risk_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n[*] 聚合数据已写入 risk_summary.json (供报告引用)")


if __name__ == "__main__":
    main()
