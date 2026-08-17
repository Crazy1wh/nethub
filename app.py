import asyncio
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
DB_PATH = os.environ.get("DB_PATH", os.path.join(DATA_DIR, "nav.db"))
ICON_DIR = os.path.join(DATA_DIR, "icons")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(ICON_DIR, exist_ok=True)

OWN_PORT = int(os.environ.get("OWN_PORT", "80"))
SUBNET = os.environ.get("SCAN_SUBNET", "192.168.1.0/24")
COMMON_PORTS = [int(x) for x in os.environ.get(
    "SCAN_PORTS",
    "80,443,3000,3001,4000,5000,66,8000,8010,8090,8092,8322,8080,8088,8081,9000,8888,9090,9443"
).split(",")]
FULL_SCAN = os.environ.get("SCAN_FULL_PORTS", "1") == "1"
SCAN_INTERVAL_H = float(os.environ.get("SCAN_INTERVAL_HOURS", "6"))
CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", "0.4"))
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "2.5"))

UA = {"User-Agent": "nethub/1.0", "Accept": "*/*"}
TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
CHARSET_RE = re.compile(rb"charset=[\"']?([\w-]+)", re.I)
LINK_ICON_RE = re.compile(rb"<link[^>]*rel=[\"']?(?:shortcut\s+)?icon[\"']?[^>]*href=[\"']([^\"']+)[\"']", re.I)
# 内网多为自签证书, 探测时跳过校验
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
_scan_lock = threading.Lock()
_scan_running = [False]

app = FastAPI(title="nethub")


# ---------- DB ----------
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS sites(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE,
            icon TEXT DEFAULT '',
            group_name TEXT DEFAULT '',
            source TEXT DEFAULT 'auto',
            hidden INTEGER DEFAULT 0,
            status TEXT DEFAULT 'unknown',
            status_code INTEGER,
            title TEXT,
            host_ip TEXT DEFAULT '',
            last_seen TEXT,
            first_seen TEXT,
            updated_at TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS scan_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT, finished_at TEXT,
            found INTEGER, total TEXT, detail TEXT
        )""")


def migrate_db():
    """旧库升级: host_ip 列 + 自动分组迁到 host_ip + 清空旧 auto 站点(混有非网页端口, 由新扫描只收网页重建)"""
    with db() as c:
        cols = [r[1] for r in c.execute("PRAGMA table_info(sites)")]
        if "host_ip" not in cols:
            c.execute("ALTER TABLE sites ADD COLUMN host_ip TEXT DEFAULT ''")
            c.execute("UPDATE sites SET host_ip=group_name WHERE source='auto' AND group_name!=''")
            c.execute("UPDATE sites SET group_name='' WHERE source='auto'")
            # 旧行未存 content-type, 无法事后判定是否网页(200 无 title 可能是 json API 也可能是网页),
            # 一次性清空, 由启动后的新扫描按网页规则重建
            c.execute("DELETE FROM sites WHERE source='auto'")
        if "favorite" not in cols:
            c.execute("ALTER TABLE sites ADD COLUMN favorite INTEGER DEFAULT 0")


# ---------- 发现 ----------
def my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(1)
        s.connect(("192.168.1.1", 9))  # UDP connect 不出包, 仅用于取本机 IP
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def scan_ports(hosts, ports, timeout=CONNECT_TIMEOUT, workers=300):
    found = set()

    def check(hp):
        h, p = hp
        s = socket.socket()
        s.settimeout(timeout)
        try:
            if s.connect_ex((h, p)) == 0:
                return (h, p)
        except Exception:
            pass
        finally:
            s.close()
        return None

    with concurrent.futures.ThreadPoolExecutor(workers) as ex:
        for r in ex.map(check, [(h, p) for h in hosts for p in ports]):
            if r:
                found.add(r)
    return found


def full_port_scan(hosts, timeout=0.15, workers=600):
    found = set()
    ports = range(1, 65536)

    def check(hp):
        h, p = hp
        s = socket.socket()
        s.settimeout(timeout)
        try:
            if s.connect_ex((h, p)) == 0:
                return (h, p)
        except Exception:
            pass
        finally:
            s.close()
        return None

    with concurrent.futures.ThreadPoolExecutor(workers) as ex:
        for r in ex.map(check, [(h, p) for h in hosts for p in ports]):
            if r:
                found.add(r)
    return found


def probe(url):
    """GET url, 返回 status/title/final_url 或 None"""
    req = urllib.request.Request(url, headers=UA)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=SSL_CTX)) if url.startswith("https://") else urllib.request.build_opener()
    body = b""
    final = url
    ctype = ""
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT) as r:
            status = r.status
            body = r.read(65536)
            final = r.geturl()
            ctype = r.headers.get("Content-Type", "") or ""
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            body = e.read(65536)
        except Exception:
            pass
        final = url
        ctype = e.headers.get("Content-Type", "") or ""
    except Exception:
        return None
    title = ""
    m = TITLE_RE.search(body)
    if m:
        raw = m.group(1).strip()
        enc = "utf-8"
        cm = CHARSET_RE.search(body[:2000])
        if cm:
            try:
                enc = cm.group(1).decode("ascii").lower()
            except Exception:
                pass
        for e in (enc, "utf-8", "gbk"):
            try:
                title = raw.decode(e, "replace").strip()[:80]
                break
            except Exception:
                continue
    return {"status": status, "title": title, "final_url": final, "ctype": ctype, "body": body}


def guess_ext(data, ctype):
    ct = (ctype or "").lower()
    if data[:8] == b"\x89PNG\r\n\x1a\n" or "png" in ct:
        return "png"
    head = data.lstrip()[:5].lower()
    if "svg" in ct or head.startswith(b"<svg") or head.startswith(b"<?xm"):
        return "svg"
    if data[:3] == b"\xff\xd8\xff" or "jpeg" in ct or "jpg" in ct:
        return "jpg"
    return "ico"


def fetch_favicon(url, body=b""):
    """按 HTML <link rel=icon> 声明优先, 其次 /favicon.ico; 返回 saved:文件名 或空"""
    candidates = []
    m = LINK_ICON_RE.search(body)
    if m:
        try:
            candidates.append(urljoin(url, m.group(1).decode("utf-8", "replace").strip()))
        except Exception:
            pass
    candidates.append(url.rstrip("/") + "/favicon.ico")
    for cu in candidates:
        try:
            req = urllib.request.Request(cu, headers=UA)
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX)) if cu.startswith("https://") else urllib.request.build_opener()
            with opener.open(req, timeout=2) as r:
                if r.status == 200:
                    data = r.read()
                    if data and len(data) < 300000:
                        ext = guess_ext(data, r.headers.get("Content-Type", ""))
                        fn = f"{hashlib.md5(data).hexdigest()[:16]}.{ext}"
                        with open(os.path.join(ICON_DIR, fn), "wb") as f:
                            f.write(data)
                        return f"saved:{fn}"
        except Exception:
            continue
    return ""


def run_scan():
    if _scan_running[0]:
        return {"skipped": True}
    _scan_running[0] = True
    started = dt.datetime.now()
    detail = []
    try:
        own = my_ip()
        net = ipaddress.ip_network(SUBNET, strict=False)
        hosts_common = [str(x) for x in net.hosts()][:512]
        found = scan_ports(hosts_common, COMMON_PORTS)
        if FULL_SCAN:
            found |= full_port_scan({own, "127.0.0.1"})
        results = []
        found_sorted = sorted(found)

        def probe_one(hp):
            ip, port = hp
            if port == OWN_PORT:
                return None
            schemes = ("https", "http") if port == 443 else ("http", "https")
            for scheme in schemes:
                url = f"{scheme}://{ip}:{port}/"
                info = probe(url)
                if info:
                    sc = info["status"]
                    ct = (info["ctype"] or "").lower()
                    t = info["title"]
                    # 只收录真网页: 2xx/3xx 需 html 或带 <title>; 401/403 需 html 且带 title;
                    # 404/5xx、json API、无 title 纯文本(设备/API 端口)一律过滤
                    if 200 <= sc < 400:
                        web = ("html" in ct) or bool(t)
                    elif sc in (401, 403):
                        web = ("html" in ct) and bool(t)
                    else:
                        web = False
                    if not web:
                        return None
                    status = "online" if sc < 400 else "auth"
                    return {
                        "url": url,
                        "host": ip,
                        "port": port,
                        "name": t or f"{ip}:{port}",
                        "title": t,
                        "icon": fetch_favicon(url, info.get("body") or b""),
                        "status": status,
                        "status_code": sc,
                        "group": "",
                    }
            return None

        with concurrent.futures.ThreadPoolExecutor(16) as ex:
            probed = [r for r in ex.map(probe_one, found_sorted) if r]

        # 同一端口同时发现 127.0.0.1 与本机 IP 时, 保留本机 IP(其他设备可达), 丢弃回环
        own_ports = {r["port"] for r in probed if r["host"] == own}
        results = [r for r in probed if not (r["host"] == "127.0.0.1" and r["port"] in own_ports)]
        for r in results:
            detail.append(f"{r['url']} -> {r['status_code']} {r['title'] or ''}".strip())
        now = dt.datetime.now().isoformat(timespec="seconds")
        with db() as c:
            for r in results:
                row = c.execute("SELECT id, host_ip, icon FROM sites WHERE url=?", (r["url"],)).fetchone()
                if row:
                    host_ip = row["host_ip"] or r["host"]
                    # 已存在站点: 刷新状态/标题; icon 为空才补抓, 不覆盖用户已有图标
                    if not row["icon"] and r["icon"]:
                        c.execute("UPDATE sites SET status=?, status_code=?, title=?, host_ip=?, icon=?, last_seen=?, updated_at=? WHERE id=?",
                                  (r["status"], r["status_code"], r["title"], host_ip, r["icon"], now, now, row["id"]))
                    else:
                        c.execute("UPDATE sites SET status=?, status_code=?, title=?, host_ip=?, last_seen=?, updated_at=? WHERE id=?",
                                  (r["status"], r["status_code"], r["title"], host_ip, now, now, row["id"]))
                else:
                    c.execute("""INSERT INTO sites(name,url,icon,group_name,source,status,status_code,title,host_ip,last_seen,first_seen,updated_at)
                                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                              (r["name"], r["url"], r["icon"], r["group"], "auto",
                               r["status"], r["status_code"], r["title"], r["host"], now, now, now))
        with db() as c:
            c.execute("INSERT INTO scan_log(started_at, finished_at, found, total, detail) VALUES(?,?,?,?,?)",
                      (started.isoformat(timespec="seconds"), now, len(results), str(len(detail)), "\n".join(detail)))
        return {"found": len(results), "detail": detail}
    finally:
        _scan_running[0] = False


def scanner_loop():
    while True:
        try:
            run_scan()
        except Exception as e:
            print("scan error:", e)
        time.sleep(SCAN_INTERVAL_H * 3600)


# ---------- API ----------
@app.on_event("startup")
def startup():
    init_db()
    migrate_db()
    t = threading.Thread(target=scanner_loop, daemon=True)
    t.start()


@app.get("/")
def index():
    # no-cache: 每次打开都重新取最新页面, 避免浏览器缓存旧版 HTML
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"),
                        headers={"Cache-Control": "no-cache"})


@app.get("/favicon.ico")
def favicon():
    return FileResponse(os.path.join(BASE_DIR, "static", "favicon.svg"), media_type="image/svg+xml")


@app.get("/api/sites")
def list_sites():
    with db() as c:
        rows = c.execute("SELECT * FROM sites ORDER BY group_name, name").fetchall()
    return {"own_ip": my_ip(), "sites": [dict(r) for r in rows]}


@app.post("/api/sites")
async def add_site(req: Request):
    body = await req.json()
    url = (body.get("url") or "").strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL 需以 http:// 或 https:// 开头")
    info = probe(url + "/")
    now = dt.datetime.now().isoformat(timespec="seconds")
    name = (body.get("name") or "").strip() or (info or {}).get("title") or url
    # 从 URL 解析 host_ip(仅 IPv4)
    host_ip = ""
    try:
        from urllib.parse import urlparse
        h = urlparse(url).hostname or ""
        socket.inet_aton(h)
        host_ip = h
    except Exception:
        pass
    with db() as c:
        try:
            cur = c.execute("""INSERT INTO sites(name,url,icon,group_name,source,status,status_code,title,host_ip,last_seen,first_seen,updated_at)
                               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (name, url, (body.get("icon") or ""), (body.get("group") or "").strip() or "手工",
                             "manual", (info or {}).get("status") and ("online" if 200 <= info["status"] < 400 else "auth" if info["status"] in (401, 403) else "offline") or "unknown",
                             (info or {}).get("status"), (info or {}).get("title"), host_ip, now, now, now))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "该 URL 已存在")
    return {"id": cur.lastrowid}


@app.put("/api/sites/{sid}")
async def update_site(sid: int, req: Request):
    body = await req.json()
    fields = []
    vals = []
    for k in ("name", "group_name", "icon"):
        if k in body and body[k] is not None:
            fields.append(f"{k}=?")
            vals.append(str(body[k]).strip())
    if "hidden" in body and body["hidden"] is not None:
        fields.append("hidden=?")
        vals.append(1 if body["hidden"] else 0)
    if "favorite" in body and body["favorite"] is not None:
        fields.append("favorite=?")
        vals.append(1 if body["favorite"] else 0)
    if not fields:
        raise HTTPException(400, "无可更新字段")
    fields.append("updated_at=?")
    vals.append(dt.datetime.now().isoformat(timespec="seconds"))
    vals.append(sid)
    with db() as c:
        c.execute(f"UPDATE sites SET {', '.join(fields)} WHERE id=?", vals)
    return {"ok": True}


@app.delete("/api/sites/{sid}")
def delete_site(sid: int):
    with db() as c:
        c.execute("DELETE FROM sites WHERE id=?", (sid,))
    return {"ok": True}


@app.post("/api/scan")
def trigger_scan():
    if _scan_running[0]:
        return {"running": True}
    threading.Thread(target=run_scan, daemon=True).start()
    return {"running": True}


@app.get("/api/scan/status")
def scan_status():
    with db() as c:
        row = c.execute("SELECT * FROM scan_log ORDER BY id DESC LIMIT 1").fetchone()
    return {"running": _scan_running[0], "last": dict(row) if row else None}


ICON_RE = re.compile(r"^[0-9a-f]{16}\.(ico|png|svg|jpg)$")


@app.get("/icons/{fn}")
def icon(fn: str):
    if not ICON_RE.match(fn):
        raise HTTPException(400, "bad icon name")
    p = os.path.join(ICON_DIR, fn)
    if not os.path.exists(p):
        raise HTTPException(404, "not found")
    return FileResponse(p)


app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
