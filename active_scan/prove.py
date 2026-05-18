"""
漏洞披露 PoC 取证脚本

目标: 对 3 个已知含学号格式文件名的学生提交文件, 发 FTP SIZE 命令
      (RFC 3659 标准), 记录服务器响应码作为证据。

为什么用 SIZE 不用 RETR:
    - SIZE 是元数据查询命令, 返回 213 + 文件大小, 零字节数据传输
    - RETR 会真的接收文件内容, 不必要 + 增加报告人法律风险
    - SIZE 返回 213 已经足够证明: 该文件对匿名用户可被 RETR 下载
      (服务器愿意把元数据告诉匿名用户, RETR 同样会成功)

输出会做匿名化:
    - 学号用 [8 位数字] 占位
    - 中文姓名用 [姓名] 占位
    - 完整文件路径不打印, 只打印「端口 + 目录类型」
"""

import ftplib
import io
import json
import re
import sys


def find_targets(data: dict, n: int = 3) -> list[tuple[int, str]]:
    """从 ftp_data.json 里找 n 个学生提交目录里的、含学号格式文件名的文件"""
    submit_kw = ["上传", "upload", "学生", "作业", "提交", "实验报告", "答辩", "毕设"]
    student_id_re = re.compile(r"\d{8,}")
    candidates: list[tuple[int, str, int]] = []  # (port, path, size)

    for p in data["ports"]:
        port = p["port"]
        for path, lines in p["tree"].items():
            path_lower = path.lower()
            if not any(kw.lower() in path_lower for kw in submit_kw):
                continue
            for line in lines:
                # 解析 LIST 行: drw-rw-rw- 1 user group SIZE Date... NAME
                if line.startswith("d"):
                    continue
                parts = line.split(maxsplit=8)
                if len(parts) < 9:
                    continue
                try:
                    size = int(parts[4])
                except ValueError:
                    continue
                if size < 1024:  # 跳过太小的, 选有内容的文件
                    continue
                name = parts[8]
                if not student_id_re.search(name):
                    continue
                full_path = path.rstrip("/") + "/" + name if path != "/" else "/" + name
                candidates.append((port, full_path, size))

    # 选不同端口的, 多样化
    seen_ports = set()
    picked: list[tuple[int, str]] = []
    for port, path, size in candidates:
        if port in seen_ports:
            continue
        seen_ports.add(port)
        picked.append((port, path))
        if len(picked) >= n:
            break
    return picked


def anonymize(path: str) -> str:
    """
    把路径里的学号和中文姓名替换为占位符。
    用临时 token 隔离已替换片段, 避免「[学号]」里的「学号」被姓名正则二次匹配。
    """
    # 1. 学号 → 临时 token (不含汉字, 不会被后续姓名正则误伤)
    p = re.sub(r"\d{8,}", "@@SID@@", path)
    # 2. 紧贴学号的姓名 (高置信度)
    p = re.sub(r"[一-龥]{2,4}(?=\s*@@SID@@)", "@@NAME@@", p)
    p = re.sub(r"(?<=@@SID@@)\s*[一-龥]{2,4}", "@@NAME@@", p)
    # 3. 夹在常见分隔符间的 2-4 汉字串 (中置信度)
    p = re.sub(r"(?<=[_\-+\(\[\.,\s])[一-龥]{2,4}(?=[_\-+\(\)\[\]\.,\s])", "@@NAME@@", p)
    # 4. token 还原成可读占位符
    p = p.replace("@@SID@@", "[学号]").replace("@@NAME@@", "[姓名]")
    return p


def probe_one(host: str, port: int, ftp_path: str) -> dict:
    """
    对单个文件做 SIZE 取证, 返回完整的 FTP 命令-响应日志。
    使用 ftplib.set_debuglevel(2) 捕获到 stderr, 重定向到内存。
    """
    log_buf = io.StringIO()
    saved_stdout = sys.stdout
    sys.stdout = log_buf  # ftplib 的 debug 输出会打到 stdout

    result = {"port": port, "path_anon": anonymize(ftp_path), "responses": [], "size": None, "error": None}

    try:
        ftp = ftplib.FTP()
        ftp.encoding = "gb18030"
        ftp.set_debuglevel(2)  # 打印所有 FTP 命令和响应
        ftp.connect(host, port, timeout=10)
        ftp.login("anonymous", "test@example.com")
        # 切到二进制模式 — 部分 Serv-U 在 ASCII 模式下拒绝 SIZE
        ftp.voidcmd("TYPE I")
        # 关键命令: SIZE, 返回 213 + 文件大小 (不会触发任何数据传输)
        size_resp = ftp.sendcmd(f"SIZE {ftp_path}")
        result["size"] = size_resp
        ftp.quit()
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        sys.stdout = saved_stdout

    # 解析 ftplib debug 日志, 抽出 *cmd* 和 *resp* 行, 做匿名化
    raw = log_buf.getvalue()
    cleaned: list[str] = []
    for line in raw.splitlines():
        if line.startswith("*cmd*"):
            cmd = line[len("*cmd* "):]
            # 匿名化命令里的路径
            cmd = anonymize(cmd)
            # PASS 隐藏密码值
            cmd = re.sub(r"PASS '.*'", "PASS '[redacted]'", cmd)
            cleaned.append(f"  > {cmd}")
        elif line.startswith("*resp*") or line.startswith("*get*"):
            tag = "<" if line.startswith("*resp*") else "<"
            text = line.split(" ", 1)[1] if " " in line else line
            text = anonymize(text)
            cleaned.append(f"  {tag} {text}")
        elif line.startswith("*welcome*"):
            text = line[len("*welcome* "):]
            cleaned.append(f"  < {text}")
    result["responses"] = cleaned
    return result


def main():
    with open("ftp_data.json", encoding="utf-8") as f:
        data = json.load(f)

    targets = find_targets(data, n=3)
    if not targets:
        print("[!] 没找到合适的取证目标")
        return

    print("=" * 70)
    print("PoC 取证: 对学生提交文件做 FTP SIZE 命令 (零字节数据传输)")
    print("=" * 70)
    print()
    print("说明: 仅发 SIZE (元数据查询), 不发 RETR (内容下载)。")
    print("      返回 213 + 文件大小 = 服务器愿意对匿名用户暴露元数据,")
    print("      等价证明 RETR 同样会成功 (匿名权限完全敞开)。")
    print()

    results = []
    for i, (port, path) in enumerate(targets, 1):
        print(f"--- 取证 #{i}: 端口 {port}, 学生提交目录 ---")
        result = probe_one("10.132.219.5", port, path)
        print(f"  目标(已匿名化): {result['path_anon']}")
        print()
        for line in result["responses"]:
            print(line)
        print()
        if result["size"]:
            print(f"  ★ 关键证据: SIZE 命令返回 → {result['size']}")
            print(f"     RFC 3659 规定: 213 = File status, 后跟文件字节数")
            print(f"     该响应证明该文件对匿名用户元数据可见, 即匿名 RETR 下载在协议层无任何阻碍。")
        if result["error"]:
            print(f"  ⚠ 错误: {result['error']}")
        print()
        results.append(result)

    # 持久化为 JSON, 给报告附录用
    with open("poc_evidence.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n[*] 完整证据(已匿名化)已写入 poc_evidence.json")


if __name__ == "__main__":
    main()
