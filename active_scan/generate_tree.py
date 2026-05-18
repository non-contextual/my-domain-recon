"""
读取 ftp_data.json, 生成自包含的交互式 HTML 树。

用法:
    python generate_tree.py ftp_data.json ftp_tree.html

特性:
    - 顶部搜索框: 输入关键词实时高亮命中节点, 自动展开包含命中的父节点
    - 每个 FTP 端口顶部展示自动推断的「课程标签」(根据子目录名出现的关键词)
    - 标记「现代数据库」相关端口, 默认展开它
    - 文件大小转人类可读 (KB / MB / GB)
    - 文件名按扩展名加 emoji 图标
    - 点端口标题复制 ftp:// URL
"""

import json
import re
import sys
import html as html_escape
from collections import Counter
from urllib.parse import quote


# 关键词 → 标签映射: 每个端口的所有目录/文件名出现关键词次数, 用最频繁的几个做标签
TOPIC_KEYWORDS = {
    "数据库": "🗄️ 数据库",
    "database": "🗄️ 数据库",
    "modern-db": "⭐ 现代数据库",
    "现代": "⭐ 现代",
    "dbms": "🗄️ 数据库",
    "sql": "🗄️ SQL",
    "mysql": "🗄️ MySQL",
    "oracle": "🗄️ Oracle",
    "数据结构": "🌲 数据结构",
    "算法": "🧮 算法",
    "数据挖掘": "⛏️ 数据挖掘",
    "大数据": "📊 大数据",
    "数据分析": "📈 数据分析",
    "数据可视化": "📊 数据可视化",
    "数据科学": "🔬 数据科学",
    "网络": "🌐 网络",
    "network": "🌐 网络",
    "电路": "⚡ 电路",
    "circuit": "⚡ 电路",
    "操作系统": "🖥️ 操作系统",
    "编译": "🛠️ 编译原理",
    "python": "🐍 Python",
    "java": "☕ Java",
    "web": "🌍 Web",
    "人工智能": "🤖 AI",
    "深度学习": "🧠 深度学习",
    "机器学习": "🧠 机器学习",
    "tensorflow": "🧠 TensorFlow",
    "毕业设计": "🎓 毕业设计",
    "毕设": "🎓 毕业设计",
    "课程设计": "📝 课程设计",
    "实验报告": "🧪 实验报告",
    "教学大纲": "📚 教学大纲",
    "考试": "📋 考试",
    "ppt": "📑 PPT",
    "experiments": "🧪 实验",
    "english": "🇬🇧 英语",
}

# 文件扩展名 → emoji
EXT_ICONS = {
    "pdf": "📕", "doc": "📘", "docx": "📘", "ppt": "📙", "pptx": "📙",
    "xls": "📗", "xlsx": "📗", "txt": "📄", "md": "📄", "rtf": "📄",
    "zip": "🗜️", "rar": "🗜️", "7z": "🗜️", "tar": "🗜️", "gz": "🗜️",
    "sql": "🗄️", "db": "🗄️", "sqlite": "🗄️",
    "py": "🐍", "java": "☕", "js": "📜", "ts": "📜", "html": "🌍",
    "c": "⚙️", "cpp": "⚙️", "h": "⚙️", "go": "🐹", "rs": "🦀",
    "mp4": "🎬", "mp3": "🎵", "wav": "🎵", "asf": "🎬", "avi": "🎬", "mkv": "🎬",
    "jpg": "🖼️", "jpeg": "🖼️", "png": "🖼️", "gif": "🖼️", "bmp": "🖼️",
    "exe": "⚙️", "msi": "📦", "iso": "💿",
}


def parse_listing_line(line: str) -> dict | None:
    """
    解析 UNIX 风格 LIST 输出:
      "drw-rw-rw-   1 user     group           0 Sep  9  2019 dirname"
    返回 {is_dir, size, date, name}, 解析失败返回 None。
    """
    if not line or line[0] not in "d-l":
        return None
    parts = line.split(maxsplit=8)
    if len(parts) < 9:
        return None
    is_dir = line.startswith("d")
    try:
        size = int(parts[4])
    except ValueError:
        size = 0
    # 日期由 parts[5..7] 构成 (Mon Day Year/Time)
    date = " ".join(parts[5:8])
    name = parts[8]
    if name in (".", ".."):
        return None
    return {"is_dir": is_dir, "size": size, "date": date, "name": name}


def human_size(n: int) -> str:
    """123456 -> '120.6 KB'"""
    if n == 0:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}".replace(".0 ", " ")
        n /= 1024
    return f"{n:.1f} PB"


def file_icon(name: str, is_dir: bool) -> str:
    if is_dir:
        return "📁"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return EXT_ICONS.get(ext, "📄")


def infer_tags(port_data: dict, max_tags: int = 4) -> list[str]:
    """根据端口下所有目录/文件名出现的关键词频率, 推断 top N 个课程标签"""
    counter = Counter()
    for path, lines in port_data["tree"].items():
        text = path.lower() + "\n" + "\n".join(l.lower() for l in lines)
        for kw, tag in TOPIC_KEYWORDS.items():
            n = text.count(kw.lower())
            if n:
                counter[tag] += n
    return [t for t, _ in counter.most_common(max_tags)]


def build_tree_from_listings(tree_dict: dict) -> dict:
    """
    把 ftplib 返回的 {"/": [LIST 行...], "/sub": [...]} 重新组织成嵌套的树:
    {
      "name": "/",
      "is_dir": True,
      "children": [
        {"name": "download", "is_dir": True, "children": [...]},
        {"name": "readme.txt", "is_dir": False, "size": 1024, "date": "..."},
      ]
    }
    """
    # 先解析每个路径下的条目
    parsed: dict[str, list[dict]] = {}
    for path, lines in tree_dict.items():
        items = [parse_listing_line(l) for l in lines]
        parsed[path] = [it for it in items if it is not None]

    def build(path: str) -> dict:
        node = {"name": path.rsplit("/", 1)[-1] or "/",
                "is_dir": True, "children": []}
        for entry in parsed.get(path, []):
            child_path = (path.rstrip("/") + "/" + entry["name"]) if path != "/" \
                         else "/" + entry["name"]
            if entry["is_dir"]:
                # 如果这个子目录在 parsed 里有更深的条目, 递归; 否则就只显示名字
                if child_path in parsed:
                    sub = build(child_path)
                    sub["date"] = entry["date"]
                    node["children"].append(sub)
                else:
                    node["children"].append({
                        "name": entry["name"], "is_dir": True,
                        "date": entry["date"], "children": [],
                        "unexplored": True,  # 标记: 没递归到这里, 只知道有
                    })
            else:
                node["children"].append({
                    "name": entry["name"], "is_dir": False,
                    "size": entry["size"], "date": entry["date"],
                })
        return node
    return build("/")


def url_encode_path(path: str) -> str:
    """对 FTP 路径做 URL 编码, 保留 / 作为分隔符"""
    return quote(path, safe="/")


def render_node(node: dict, port: int, parent_path: str, depth: int = 0) -> str:
    """
    递归把树节点渲染成 HTML <li>...

    port:        当前所在 FTP 端口号
    parent_path: 当前节点在 FTP 上的父目录路径 (以 / 开头, 不带末尾 /)
    """
    name = html_escape.escape(node["name"])
    raw_name = node["name"]
    # 拼当前节点的完整 FTP 路径
    full_path = (parent_path.rstrip("/") + "/" + raw_name) if parent_path != "/" else "/" + raw_name

    if node["is_dir"]:
        children = node.get("children", [])
        unexplored = node.get("unexplored")
        cnt = len(children)
        # 「未深入」的目录 — 可异步展开 (data-port + data-path)
        if unexplored:
            return (
                f"<li class='dir-lazy' data-port='{port}' "
                f"data-path='{html_escape.escape(full_path)}'>"
                f"<details>"
                f"<summary>"
                f"<span class='icon'>📁</span>"
                f"<span class='name'>{name}/</span>"
                f"<span class='hint lazy-hint'>📡 点击实时加载</span>"
                f"</summary>"
                f"<ul class='lazy-target'><li class='loading'>正在拉取…</li></ul>"
                f"</details>"
                f"</li>"
            )
        # 空目录, 不可展开
        if cnt == 0:
            return (
                f"<li class='leaf-dir'>"
                f"<span class='icon'>📁</span>"
                f"<span class='name'>{name}/</span>"
                f"<span class='hint'>空</span>"
                f"</li>"
            )
        # 已抓到内容的可展开目录
        meta = f"<span class='count'>({cnt} 项)</span>"
        kids_html = "".join(render_node(c, port, full_path, depth + 1) for c in children)
        return (
            f"<li class='dir'>"
            f"<details>"
            f"<summary><span class='icon'>📁</span><span class='name'>{name}/</span>{meta}</summary>"
            f"<ul>{kids_html}</ul>"
            f"</details>"
            f"</li>"
        )
    else:
        # 文件 → 下载链接, 走本地代理 /dl/<port>/<encoded path>
        size_h = human_size(node.get("size", 0))
        size_html = f"<span class='size'>{size_h}</span>" if size_h else ""
        download_url = f"/dl/{port}{url_encode_path(full_path)}"
        return (
            f"<li class='file'>"
            f"<a class='download' href='{download_url}' download='{html_escape.escape(raw_name)}' "
            f"title='点击下载 (需要本地代理已启动)'>"
            f"<span class='icon'>{file_icon(raw_name, False)}</span>"
            f"<span class='name'>{name}</span>"
            f"</a>"
            f"{size_html}"
            f"</li>"
        )


def classify_modern_db(port_data: dict) -> str:
    """
    判断端口与「现代数据库」的关系:
        "source"   - 含 modern-dbsystem 目录, 是课程资料源
        "student"  - 含「现代数据库」字样但没 modern-dbsystem, 是学生作业归档
        "none"     - 无关
    """
    text_lines = " ".join(line for lines in port_data["tree"].values() for line in lines)
    if "modern-dbsystem" in text_lines.lower():
        return "source"
    if "现代数据库" in text_lines:
        return "student"
    return "none"


def render_port(host: str, port_data: dict) -> str:
    port = port_data["port"]
    tags = infer_tags(port_data)
    mdb_kind = classify_modern_db(port_data)
    is_modern_db = mdb_kind != "none"
    # 把「现代数据库」相关性强的端口的标签前面加一个明确的徽章
    if mdb_kind == "source":
        tags = ["⭐ 现代数据库 (资料源)"] + [t for t in tags if "现代" not in t]
    elif mdb_kind == "student":
        tags = ["⭐ 现代数据库 (学生作业)"] + [t for t in tags if "现代" not in t]
    tags_html = "".join(f"<span class='tag'>{html_escape.escape(t)}</span>" for t in tags) or \
                "<span class='tag tag-empty'>无明显主题</span>"
    star = " ⭐" if is_modern_db else ""
    classes = "port" + (" port-highlight" if is_modern_db else "")
    open_attr = " open" if is_modern_db else ""
    tree = build_tree_from_listings(port_data["tree"])
    children_html = "".join(render_node(c, port, "/") for c in tree["children"])
    url = f"ftp://{host}:{port}/"
    return f"""
<div class="{classes}" data-port="{port}">
  <details{open_attr}>
    <summary>
      <span class="port-num">:{port}{star}</span>
      <span class="port-tags">{tags_html}</span>
      <button class="copy-btn" data-url="{html_escape.escape(url)}" title="复制 FTP 地址">📋 {html_escape.escape(url)}</button>
    </summary>
    <ul class="tree">{children_html}</ul>
  </details>
</div>"""


def main():
    if len(sys.argv) != 3:
        print("用法: python generate_tree.py <input.json> <output.html>")
        sys.exit(1)
    in_path, out_path = sys.argv[1], sys.argv[2]
    with open(in_path, encoding="utf-8") as f:
        data = json.load(f)
    host = data["host"]
    ports = data["ports"]

    # 把「现代数据库」相关的端口排到最前面: 资料源 > 学生作业 > 其它
    def sort_key(p):
        kind = classify_modern_db(p)
        rank = {"source": 0, "student": 1, "none": 2}[kind]
        return (rank, p["port"])
    ports.sort(key=sort_key)

    ports_html = "\n".join(render_port(host, p) for p in ports)

    page = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{html_escape.escape(host)} FTP 端口树</title>
<style>
  :root {{
    --bg: #fafaf7; --fg: #2c2c2c; --muted: #888; --accent: #d4651a;
    --card: #fff; --border: #e8e4dc; --highlight: #fff4d6;
    --tag-bg: #f0ede5; --tag-fg: #5a4a2e;
    --hit: #ffe27a;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
    background: var(--bg); color: var(--fg); margin: 0; line-height: 1.55;
  }}
  header {{
    position: sticky; top: 0; background: var(--bg); border-bottom: 1px solid var(--border);
    padding: 16px 24px; z-index: 10;
  }}
  h1 {{ margin: 0 0 8px; font-size: 18px; font-weight: 600; }}
  .meta {{ color: var(--muted); font-size: 13px; }}
  #search {{
    width: 100%; padding: 10px 14px; font-size: 15px;
    border: 1px solid var(--border); border-radius: 8px; margin-top: 12px;
    background: var(--card); color: var(--fg);
  }}
  #search:focus {{ outline: none; border-color: var(--accent); }}
  main {{ max-width: 1100px; margin: 0 auto; padding: 16px 24px 80px; }}

  .port {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; margin-bottom: 12px; overflow: hidden;
  }}
  .port-highlight {{ border-color: var(--accent); box-shadow: 0 2px 12px rgba(212, 101, 26, 0.15); }}
  .port > details > summary {{
    list-style: none; cursor: pointer; padding: 12px 16px;
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    background: linear-gradient(to right, transparent, var(--card));
  }}
  .port > details[open] > summary {{ background: var(--highlight); border-bottom: 1px solid var(--border); }}
  .port-highlight > details > summary {{ background: linear-gradient(to right, #fff4d6, #fff); }}
  .port > details > summary::-webkit-details-marker {{ display: none; }}
  .port > details > summary::before {{
    content: "▸"; color: var(--accent); transition: transform 0.15s; display: inline-block;
  }}
  .port > details[open] > summary::before {{ transform: rotate(90deg); }}
  .port-num {{ font-weight: 700; font-size: 15px; color: var(--accent); min-width: 80px; }}
  .port-tags {{ display: flex; gap: 6px; flex-wrap: wrap; flex: 1; }}
  .tag {{
    background: var(--tag-bg); color: var(--tag-fg);
    padding: 2px 10px; border-radius: 12px; font-size: 12px;
  }}
  .tag-empty {{ color: var(--muted); font-style: italic; }}
  .copy-btn {{
    background: transparent; border: 1px solid var(--border); cursor: pointer;
    padding: 4px 10px; border-radius: 6px; font-size: 12px; color: var(--muted);
    font-family: ui-monospace, "SF Mono", Consolas, monospace;
  }}
  .copy-btn:hover {{ background: var(--bg); color: var(--fg); }}
  .copy-btn.copied {{ background: #c8e6c9; color: #2e7d32; border-color: #2e7d32; }}

  .tree {{ list-style: none; padding: 8px 16px 16px 16px; margin: 0; }}
  .tree ul {{ list-style: none; padding-left: 24px; margin: 0; }}
  .tree li {{
    padding: 2px 0; display: flex; align-items: baseline; gap: 6px; min-height: 22px;
  }}
  .tree li.dir, .tree li.file, .tree li.leaf-dir {{ display: list-item; }}
  .tree details > summary {{
    cursor: pointer; list-style: none; display: flex; align-items: center; gap: 6px;
  }}
  .tree details > summary::-webkit-details-marker {{ display: none; }}
  .tree details > summary::before {{
    content: "▸"; color: var(--muted); display: inline-block; transition: transform 0.1s;
    font-size: 10px; width: 10px;
  }}
  .tree details[open] > summary::before {{ transform: rotate(90deg); }}
  .tree .leaf-dir {{ padding-left: 16px; color: var(--muted); }}
  .tree .file {{ padding-left: 16px; }}
  .icon {{ display: inline-block; width: 18px; }}
  .name {{ word-break: break-all; }}
  .size {{ color: var(--muted); font-size: 12px; margin-left: 8px; font-family: ui-monospace, monospace; }}
  .count {{ color: var(--muted); font-size: 12px; margin-left: 6px; }}
  .hint {{ color: var(--muted); font-size: 12px; margin-left: 6px; font-style: italic; }}

  .hit {{ background: var(--hit); padding: 0 2px; border-radius: 3px; }}
  .port.hidden {{ display: none; }}
  .port.has-hit > details > summary {{ box-shadow: inset 4px 0 0 var(--accent); }}

  /* 文件下载链接 — 行内整体可点 */
  a.download {{ color: inherit; text-decoration: none; display: inline-flex; align-items: baseline; gap: 6px; }}
  a.download:hover {{ background: var(--highlight); border-radius: 4px; padding: 0 4px; margin: 0 -4px; }}
  a.download:hover .name {{ color: var(--accent); text-decoration: underline; }}

  /* 「未深入」的可异步展开目录 */
  .lazy-hint {{ color: #c97e3a !important; cursor: pointer; }}
  .dir-lazy details[open] .lazy-hint {{ display: none; }}
  .loading {{ color: var(--muted); font-style: italic; padding-left: 16px; }}
  .lazy-error {{ color: #c0392b; padding-left: 16px; }}

  /* 代理状态提示横幅 */
  .proxy-banner {{
    background: #fff3cd; color: #6b4f00; padding: 8px 14px;
    border: 1px solid #f0c674; border-radius: 6px; margin-bottom: 12px;
    font-size: 13px; display: none;
  }}
  .proxy-banner.show {{ display: block; }}
  .proxy-banner code {{
    background: #fff; padding: 1px 6px; border-radius: 3px;
    font-family: ui-monospace, "SF Mono", Consolas, monospace;
  }}

  .summary-bar {{
    background: #f5f1e8; padding: 8px 16px; border-radius: 8px; font-size: 13px;
    color: var(--muted); margin-bottom: 16px;
  }}
  .summary-bar b {{ color: var(--accent); }}
</style>
</head>
<body>
<header>
  <h1>📡 {html_escape.escape(host)} — FTP 端口树</h1>
  <div class="meta">{len(ports)} 个可匿名登录的 FTP 端口 · 点端口展开目录 · 输入关键词搜索</div>
  <input id="search" type="search" placeholder="🔍 搜索文件夹/文件名/端口号 (例: 现代数据库, 数据结构, 9966)" autofocus>
</header>
<main>
  <div class="summary-bar">
    💡 <b>⭐ 标记的是「现代数据库系统」课程相关端口</b>。<b>9966</b> 是 <b>资料源</b>（PPT/SQL/视频/软件），<b>2019</b> 是历年 <b>学生作业归档</b>。两个端口都已自动展开；其它端口默认折叠，点击展开。
    <br>📥 <b>点文件名直接下载</b>（需本地代理）；📡 <b>「点击实时加载」</b>的目录会现拉 FTP 列表。
  </div>
  <div class="proxy-banner" id="proxy-banner">
    ⚠️ <b>本地代理未启动</b> — 文件下载和实时展开会失败。请双击运行 <code>start.bat</code>，然后访问 <code>http://localhost:8765/</code> 而不是直接打开 HTML 文件。
  </div>
{ports_html}
</main>
<script>
  // 复制 FTP URL
  document.querySelectorAll('.copy-btn').forEach(btn => {{
    btn.addEventListener('click', e => {{
      e.preventDefault(); e.stopPropagation();
      const url = btn.dataset.url;
      navigator.clipboard.writeText(url).then(() => {{
        const orig = btn.textContent;
        btn.textContent = '✓ 已复制';
        btn.classList.add('copied');
        setTimeout(() => {{ btn.textContent = orig; btn.classList.remove('copied'); }}, 1200);
      }});
    }});
  }});

  // 搜索: 输入关键词后高亮所有匹配的文本节点, 并自动展开父级 details
  const searchInput = document.getElementById('search');
  let searchTimer = null;
  searchInput.addEventListener('input', () => {{
    clearTimeout(searchTimer);
    searchTimer = setTimeout(doSearch, 150);
  }});

  function clearHighlights() {{
    document.querySelectorAll('.hit').forEach(el => {{
      const txt = document.createTextNode(el.textContent);
      el.parentNode.replaceChild(txt, el);
    }});
    document.querySelectorAll('.port').forEach(p => {{
      p.classList.remove('hidden', 'has-hit');
    }});
  }}

  function highlightTextNodes(root, regex) {{
    let hit = false;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    const targets = [];
    let n;
    while ((n = walker.nextNode())) {{
      if (regex.test(n.nodeValue)) targets.push(n);
    }}
    targets.forEach(t => {{
      const span = document.createElement('span');
      span.innerHTML = t.nodeValue.replace(regex, m => `<span class="hit">${{m}}</span>`);
      t.parentNode.replaceChild(span, t);
      hit = true;
    }});
    return hit;
  }}

  function doSearch() {{
    clearHighlights();
    const q = searchInput.value.trim();
    if (!q) return;
    const regex = new RegExp(q.replace(/[.*+?^${{}}()|[\\]\\\\]/g, '\\\\$&'), 'gi');
    document.querySelectorAll('.port').forEach(port => {{
      const hit = highlightTextNodes(port, regex);
      if (hit) {{
        port.classList.add('has-hit');
        // 展开命中的 details (端口本身 + 内部所有有 hit 的目录)
        port.querySelectorAll('details').forEach(d => {{
          if (d.querySelector('.hit')) d.open = true;
        }});
      }} else {{
        port.classList.add('hidden');
      }}
    }});
  }}

  // ========== 代理服务器状态检测 ==========
  // 如果是用 file:// 打开的 (而非通过代理), 提示用户启动代理
  // 因为 file:// 下点 /dl/... 链接会被解析成相对 file:// 路径, 必然失败
  function checkProxy() {{
    const banner = document.getElementById('proxy-banner');
    if (location.protocol === 'file:') {{
      // 直接判定: 必须用 http://localhost:8765 才能下载
      banner.classList.add('show');
      // 把所有 /dl/ 链接改成绝对路径, 至少手动复制能用
      document.querySelectorAll('a.download').forEach(a => {{
        a.href = 'http://localhost:8765' + a.getAttribute('href');
      }});
      return;
    }}
    // 通过代理打开的, 探测一下 /ls/ 路由是否健康
    fetch('/ls/9966/', {{ method: 'GET' }})
      .then(r => {{
        if (!r.ok) banner.classList.add('show');
      }})
      .catch(() => banner.classList.add('show'));
  }}
  checkProxy();

  // ========== 「未深入」目录的异步展开 ==========
  // 用户点开一个 dir-lazy 时, 用 fetch /ls/<port>/<path> 拉真实目录, 渲染进去
  document.querySelectorAll('.dir-lazy').forEach(li => {{
    const details = li.querySelector('details');
    let loaded = false;
    details.addEventListener('toggle', () => {{
      if (!details.open || loaded) return;
      loaded = true;  // 防止反复 toggle 时重复请求
      const port = li.dataset.port;
      const path = li.dataset.path;
      const target = li.querySelector('.lazy-target');
      // FTP 路径需要做 URL 编码, 但 / 保留作分隔符
      const encodedPath = path.split('/').map(encodeURIComponent).join('/');
      const url = `/ls/${{port}}${{encodedPath}}`;
      fetch(url)
        .then(r => {{
          if (!r.ok) throw new Error(`HTTP ${{r.status}}`);
          return r.json();
        }})
        .then(data => {{
          target.innerHTML = '';
          if (!data.items || data.items.length === 0) {{
            target.innerHTML = '<li class="loading">(空目录)</li>';
            return;
          }}
          data.items.forEach(item => {{
            target.appendChild(renderLazyItem(item, port, path));
          }});
        }})
        .catch(err => {{
          target.innerHTML = `<li class="lazy-error">❌ 加载失败: ${{err.message}}<br>` +
            `&nbsp;&nbsp;请确认本地代理已启动 (双击 start.bat)</li>`;
          loaded = false;  // 失败可以重试
        }});
    }});
  }});

  // 把 /ls 返回的一个条目渲染成 <li>
  function renderLazyItem(item, port, parentPath) {{
    const li = document.createElement('li');
    const safeName = escapeHtml(item.name);
    const fullPath = (parentPath === '/' ? '' : parentPath) + '/' + item.name;
    if (item.is_dir) {{
      // 目录: 也做成可异步展开的(用同样的机制)
      li.className = 'dir-lazy';
      li.dataset.port = port;
      li.dataset.path = fullPath;
      li.innerHTML = `<details><summary>` +
        `<span class="icon">📁</span><span class="name">${{safeName}}/</span>` +
        `<span class="hint lazy-hint">📡 点击实时加载</span>` +
        `</summary><ul class="lazy-target"><li class="loading">正在拉取…</li></ul></details>`;
      // 重新绑定 toggle (递归启用懒加载)
      const det = li.querySelector('details');
      let subLoaded = false;
      det.addEventListener('toggle', () => {{
        if (!det.open || subLoaded) return;
        subLoaded = true;
        const target = li.querySelector('.lazy-target');
        const encodedPath = fullPath.split('/').map(encodeURIComponent).join('/');
        fetch(`/ls/${{port}}${{encodedPath}}`)
          .then(r => r.json())
          .then(d => {{
            target.innerHTML = '';
            if (!d.items || !d.items.length) {{
              target.innerHTML = '<li class="loading">(空目录)</li>';
              return;
            }}
            d.items.forEach(it => target.appendChild(renderLazyItem(it, port, fullPath)));
          }})
          .catch(e => {{
            target.innerHTML = `<li class="lazy-error">❌ ${{e.message}}</li>`;
            subLoaded = false;
          }});
      }});
    }} else {{
      // 文件: 下载链接
      li.className = 'file';
      const encodedPath = fullPath.split('/').map(encodeURIComponent).join('/');
      const dlUrl = `/dl/${{port}}${{encodedPath}}`;
      const sizeText = humanSize(item.size || 0);
      li.innerHTML = `<a class="download" href="${{dlUrl}}" download="${{safeName}}">` +
        `<span class="icon">${{fileIcon(item.name)}}</span>` +
        `<span class="name">${{safeName}}</span></a>` +
        (sizeText ? `<span class="size">${{sizeText}}</span>` : '');
    }}
    return li;
  }}

  function escapeHtml(s) {{
    return s.replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[c]);
  }}
  function humanSize(n) {{
    if (!n) return '';
    const units = ['B','KB','MB','GB','TB'];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) {{ n /= 1024; i++; }}
    return n.toFixed(1).replace('.0','') + ' ' + units[i];
  }}
  function fileIcon(name) {{
    const ext = (name.split('.').pop() || '').toLowerCase();
    const map = {{
      pdf: '📕', doc: '📘', docx: '📘', ppt: '📙', pptx: '📙',
      xls: '📗', xlsx: '📗', txt: '📄', md: '📄',
      zip: '🗜️', rar: '🗜️', '7z': '🗜️', tar: '🗜️', gz: '🗜️',
      sql: '🗄️', mp4: '🎬', mp3: '🎵', asf: '🎬',
      jpg: '🖼️', png: '🖼️', exe: '⚙️', msi: '📦'
    }};
    return map[ext] || '📄';
  }}
</script>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"[*] HTML 已生成: {out_path}")


if __name__ == "__main__":
    main()
