
import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import socket
import uuid
import psutil
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("NyxRelay-Gateway")

app = FastAPI(title="NyxRelay", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 7860)),
    "secret": os.environ.get("SECRET_KEY", "nyxrelay-default-secret-key"),
}


PANEL_VERSION = os.environ.get("PANEL_VERSION", "v1.0.0")
CORE_VERSION = os.environ.get("CORE_VERSION", "v26.4.25")
TELEGRAM_HANDLE = os.environ.get("TELEGRAM_HANDLE", "@NyxRelay")


SERVICE_RUNNING = True
SERVICE_STARTED_AT = time.time()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict = {}
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

# Track network baseline for speed calculation
_net_baseline = {"bytes_sent": 0, "bytes_recv": 0, "ts": time.time()}

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

CUSTOM_DOMAIN: str = ""
CUSTOM_DOMAIN_LOCK = asyncio.Lock()

SESSION_COOKIE = "nyxrelay_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {
    "password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin")),
    "username": os.environ.get("ADMIN_USERNAME", "admin"),
}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client, _net_baseline
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    

    try:
        nc = psutil.net_io_counters()
        _net_baseline = {"bytes_sent": nc.bytes_sent, "bytes_recv": nc.bytes_recv, "ts": time.time()}
    except Exception:
        _net_baseline = {"bytes_sent": 0, "bytes_recv": 0, "ts": time.time()}
    
    logger.info(f"NyxRelay started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

def get_domain() -> str:
    return os.environ.get("SPACE_HOST", "localhost").replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    # Real, standard RFC-4122 UUID
    if seed is None:
        return str(uuid.uuid4())
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "NyxRelay", address: str = None) -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def uptime_seconds() -> int:
    return int(time.time() - stats["start_time"])

def uptime() -> str:
    secs = uptime_seconds()
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def os_uptime_str() -> str:
    try:
        secs = int(time.time() - psutil.boot_time())
        d = secs // 86400
        h = (secs % 86400) // 3600
        m = (secs % 3600) // 60
        if d > 0:
            return f"{d}d {h}h {m}m"
        elif h > 0:
            return f"{h}h {m}m"
        else:
            return f"{m}m"
    except Exception:
        return "N/A"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

def compute_expiry(expiry_days) -> str:
    try:
        days = float(expiry_days or 0)
    except (TypeError, ValueError):
        days = 0
    if days <= 0:
        return ""
    return (datetime.now() + timedelta(days=days)).isoformat()

def is_expired(link) -> bool:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return False
    try:
        return datetime.now() >= datetime.fromisoformat(exp)
    except (TypeError, ValueError):
        return False

def expiry_epoch(link) -> int:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return 0
    try:
        return int(datetime.fromisoformat(exp).timestamp())
    except (TypeError, ValueError):
        return 0

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            uid = generate_uuid()
            LINKS[uid] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "max_connections": 0, "created_at": datetime.now().isoformat(), "active": True, "expiry": ""}

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))

def remove_ip_from_link(uid: str, ip: str):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]:
            link_ip_map.pop(uid, None)

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)

def get_real_ips():
    ipv4 = ""
    ipv6 = ""
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    ipv4 = addr.address
                elif addr.family == socket.AF_INET6 and not addr.address.startswith("::1") and not addr.address.startswith("fe80"):
                    ipv6 = addr.address.split("%")[0]
    except Exception:
        pass
    return ipv4, ipv6

def get_net_speed():
    global _net_baseline
    try:
        nc = psutil.net_io_counters()
        now = time.time()
        elapsed = now - _net_baseline["ts"]
        if elapsed < 0.1:
            elapsed = 1.0
        up_bps = (nc.bytes_sent - _net_baseline["bytes_sent"]) / elapsed
        down_bps = (nc.bytes_recv - _net_baseline["bytes_recv"]) / elapsed
        _net_baseline = {"bytes_sent": nc.bytes_sent, "bytes_recv": nc.bytes_recv, "ts": now}
        return nc.bytes_sent, nc.bytes_recv, up_bps, down_bps
    except Exception:
        return 0, 0, 0, 0

def fmt_bytes_speed(bps: float) -> str:
    if bps >= 1_048_576:
        return f"{bps/1_048_576:.2f} MB"
    elif bps >= 1024:
        return f"{bps/1024:.2f} KB"
    else:
        return f"{bps:.0f} B"

def fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824:
        return f"{b/1_073_741_824:.2f} GB"
    elif b >= 1_048_576:
        return f"{b/1_048_576:.2f} MB"
    elif b >= 1024:
        return f"{b/1024:.1f} KB"
    return f"{b} B"

def get_net_connections_count():
    try:
        conns = psutil.net_connections()
        tcp = sum(1 for c in conns if c.type == socket.SOCK_STREAM)
        udp = sum(1 for c in conns if c.type == socket.SOCK_DGRAM)
        return tcp, udp
    except Exception:
        return 0, 0

@app.get("/")
async def root(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return RedirectResponse(url="/login")

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    username = str(body.get("username") or "")
    # Accept if username matches (or blank) AND password matches
    if username and username != AUTH["username"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }

@app.get("/api/stats")
async def get_api_stats(_=Depends(require_auth)):
    cpu = psutil.cpu_percent(interval=0.1)
    vm = psutil.virtual_memory()
    ram_pct = vm.percent
    ram_used_mb = vm.used / 1_048_576
    ram_total_mb = vm.total / 1_048_576

    load_avg = [0.0, 0.0, 0.0]
    try:
        load_avg = list(os.getloadavg())
    except Exception:
        pass

    total_sent_bytes, total_recv_bytes, up_bps, down_bps = get_net_speed()
    ipv4, ipv6 = get_real_ips()
    tcp, udp = get_net_connections_count()

    try:
        proc = psutil.Process()
        threads = proc.num_threads()
        proc_ram = proc.memory_info().rss / 1_048_576
    except Exception:
        threads = 0
        proc_ram = ram_used_mb

    # Swap (real)
    try:
        sw = psutil.swap_memory()
        swap_pct = sw.percent
        swap_used = sw.used
        swap_total = sw.total
    except Exception:
        swap_pct, swap_used, swap_total = 0.0, 0, 0

    # Storage (real, root filesystem)
    try:
        du = psutil.disk_usage("/")
        disk_pct = du.percent
        disk_used = du.used
        disk_total = du.total
    except Exception:
        disk_pct, disk_used, disk_total = 0.0, 0, 0

    # CPU cores (real)
    try:
        cpu_cores = psutil.cpu_count(logical=True) or 1
    except Exception:
        cpu_cores = 1

    # Xray (tunnel core) uptime: measured from the last (re)start of the service
    if SERVICE_RUNNING:
        xray_uptime_s = int(time.time() - SERVICE_STARTED_AT)
        if xray_uptime_s < 3600:
            xray_uptime = f"{xray_uptime_s // 60}m"
        elif xray_uptime_s < 86400:
            xray_uptime = f"{xray_uptime_s // 3600}h {(xray_uptime_s % 3600)//60}m"
        else:
            xray_uptime = f"{xray_uptime_s // 86400}d {(xray_uptime_s % 86400)//3600}h"
    else:
        xray_uptime = "Stopped"

    return {
        "cpuUsage": round(cpu, 1),
        "ramUsage": round(ram_pct, 1),
        "ramUsed": f"{ram_used_mb:.1f} MB",
        "ramTotal": f"{ram_total_mb:.0f} MB",
        "uptime": os_uptime_str(),
        "xrayUptime": xray_uptime,
        "systemLoad": f"{load_avg[0]:.2f} | {load_avg[1]:.2f} | {load_avg[2]:.2f}",
        "threads": threads,
        "uploadSpeed": fmt_bytes_speed(up_bps) + "/s",
        "downloadSpeed": fmt_bytes_speed(down_bps) + "/s",
        "totalSent": fmt_bytes(total_sent_bytes),
        "totalReceived": fmt_bytes(total_recv_bytes),
        "ipv4": ipv4 or "N/A",
        "ipv6": ipv6 or "N/A",
        "tcpConnections": tcp,
        "udpConnections": udp,
        "activeConnections": len(connections),
        "totalTrafficMb": round(stats["total_bytes"] / 1_048_576, 2),
        "totalRequests": stats["total_requests"],
        "linksCount": len(LINKS),
        "domain": get_domain(),
        "hourlyTraffic": dict(hourly_traffic),
        "recentErrors": list(error_logs)[-5:],
        "cpuCores": cpu_cores,
        "swapUsage": round(swap_pct, 1),
        "swapUsed": fmt_bytes(swap_used),
        "swapTotal": fmt_bytes(swap_total),
        "storageUsage": round(disk_pct, 1),
        "storageUsed": fmt_bytes(disk_used),
        "storageTotal": fmt_bytes(disk_total),
        "appRam": f"{proc_ram:.2f} MB",
        "xrayRunning": SERVICE_RUNNING,
        "panelVersion": PANEL_VERSION,
        "coreVersion": CORE_VERSION,
        "telegram": TELEGRAM_HANDLE,
    }

async def _stop_service_internal():
    global SERVICE_RUNNING
    SERVICE_RUNNING = False
    for cid, ws in list(connection_sockets.items()):
        try:
            await ws.close(code=1012, reason="service stopped")
        except Exception:
            pass
    connections.clear()
    connection_sockets.clear()
    link_ip_map.clear()

@app.get("/api/service")
async def service_status(_=Depends(require_auth)):
    return {"running": SERVICE_RUNNING, "core_version": CORE_VERSION,
            "active_connections": len(connections)}

@app.post("/api/service/stop")
async def service_stop(_=Depends(require_auth)):
    await _stop_service_internal()
    logger.info("Core stopped via panel")
    return {"ok": True, "running": SERVICE_RUNNING}

@app.post("/api/service/restart")
async def service_restart(_=Depends(require_auth)):
    global SERVICE_RUNNING, SERVICE_STARTED_AT
    await _stop_service_internal()
    await asyncio.sleep(0.3)
    SERVICE_RUNNING = True
    SERVICE_STARTED_AT = time.time()
    logger.info("Core restarted via panel")
    return {"ok": True, "running": SERVICE_RUNNING}

@app.get("/api/logs")
async def get_logs(_=Depends(require_auth)):
    return {
        "running": SERVICE_RUNNING,
        "totals": {
            "bytes": stats["total_bytes"],
            "requests": stats["total_requests"],
            "errors": stats["total_errors"],
        },
        "errors": list(error_logs)[-50:],
        "connections": [
            {"id": cid, "uuid": info.get("uuid"), "ip": info.get("ip"),
             "connected_at": info.get("connected_at"), "bytes": info.get("bytes", 0)}
            for cid, info in connections.items()
        ],
    }

@app.get("/api/config")
async def get_runtime_config(_=Depends(require_auth)):
    async with LINKS_LOCK:
        inbounds = [{"uuid": uid, "remark": d["label"], "enabled": d["active"],
                     "ws_path": f"/ws/{uid}"} for uid, d in LINKS.items()]
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    return {
        "panel": "NyxRelay",
        "panel_version": PANEL_VERSION,
        "core_version": CORE_VERSION,
        "running": SERVICE_RUNNING,
        "port": CONFIG["port"],
        "domain": CUSTOM_DOMAIN or get_domain(),
        "protocol": "vless",
        "network": "ws",
        "security": "tls",
        "clean_addresses": addresses,
        "inbounds": inbounds,
    }

@app.get("/api/backup")
async def download_backup(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links_copy = {uid: dict(d) for uid, d in LINKS.items()}
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    backup = {
        "panel": "NyxRelay",
        "panel_version": PANEL_VERSION,
        "core_version": CORE_VERSION,
        "exported_at": datetime.now().isoformat(),
        "domain": CUSTOM_DOMAIN,
        "addresses": addresses,
        "username": AUTH["username"],
        "password_hash": AUTH["password_hash"],
        "links": links_copy,
    }
    content = json.dumps(backup, indent=2)
    fname = f"nyxrelay-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    return Response(content=content, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})

@app.post("/api/restore")
async def restore_backup(request: Request, _=Depends(require_auth)):
    global CUSTOM_DOMAIN
    body = await request.json()
    links = body.get("links")
    if not isinstance(links, dict):
        raise HTTPException(status_code=400, detail="Invalid backup file")
    async with LINKS_LOCK:
        LINKS.clear()
        for uid, d in links.items():
            if not isinstance(d, dict):
                continue
            LINKS[uid] = {
                "label": str(d.get("label", "Restored"))[:60],
                "limit_bytes": int(d.get("limit_bytes", 0) or 0),
                "used_bytes": int(d.get("used_bytes", 0) or 0),
                "max_connections": int(d.get("max_connections", 0) or 0),
                "created_at": d.get("created_at", datetime.now().isoformat()),
                "active": bool(d.get("active", True)),
                "expiry": d.get("expiry", ""),
            }
    if isinstance(body.get("addresses"), list):
        async with CUSTOM_ADDRESSES_LOCK:
            CUSTOM_ADDRESSES.clear()
            for a in body["addresses"]:
                if isinstance(a, str) and a:
                    CUSTOM_ADDRESSES.append(a)
    if isinstance(body.get("domain"), str):
        async with CUSTOM_DOMAIN_LOCK:
            CUSTOM_DOMAIN = body["domain"]
    return {"ok": True, "restored": len(LINKS)}

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Inbound name must contain only English letters, numbers, and characters: - _ . space")
    if not label:
        raise HTTPException(status_code=400, detail="Inbound name is required")
    async with LINKS_LOCK:
        if any(d["label"].lower() == label.lower() for d in LINKS.values()):
            raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0:
        max_conn = 0
    expiry = compute_expiry(body.get("expiry_days"))
    uid = generate_uuid()   # real UUID is the connection credential
    async with LINKS_LOCK:
        LINKS[uid] = {"label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "created_at": datetime.now().isoformat(), "active": True, "expiry": expiry}
    return {"uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "active": True, "expiry": expiry, "created_at": LINKS[uid]["created_at"], "vless_link": generate_vless_link(uid, remark=f"NyxRelay-{label}")}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({"uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"], "used_bytes": data["used_bytes"], "max_connections": data.get("max_connections", 0), "active": data["active"], "expiry": data.get("expiry", ""), "expired": is_expired(data), "created_at": data["created_at"], "current_connections": count_connections_for_link(uid), "vless_link": generate_vless_link(uid, remark=f"NyxRelay-{data['label']}")})
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

# Also expose as /api/inbounds for new UI compatibility
@app.get("/api/inbounds")
async def list_inbounds(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({
                "id": uid,
                "uuid": uid,
                "remark": data["label"],
                "label": data["label"],
                "protocol": "vless",
                "enabled": data["active"],
                "active": data["active"],
                "limit_bytes": data["limit_bytes"],
                "used_bytes": data["used_bytes"],
                "total_flow": data["limit_bytes"] / 1_073_741_824 if data["limit_bytes"] > 0 else 0,
                "max_connections": data.get("max_connections", 0),
                "expiry": data.get("expiry", ""),
                "expired": is_expired(data),
                "created_at": data["created_at"],
                "current_connections": count_connections_for_link(uid),
                "vless_link": generate_vless_link(uid, remark=f"NyxRelay-{data['label']}"),
                "clients": [{"id": uid, "email": data["label"]}],
            })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"items": result, "total": len(result)}

@app.patch("/api/inbounds/{uid}")
async def patch_inbound(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="inbound not found")
        if "enabled" in body:
            LINKS[uid]["active"] = bool(body["enabled"])
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "expiry_days" in body:
            LINKS[uid]["expiry"] = compute_expiry(body.get("expiry_days"))
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "remark" in body:
            LINKS[uid]["label"] = str(body["remark"])[:60]
        if "max_connections" in body:
            mc = int(body["max_connections"] or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
    return {"ok": True}

@app.delete("/api/inbounds/{uid}")
async def delete_inbound(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "expiry_days" in body:
            LINKS[uid]["expiry"] = compute_expiry(body.get("expiry_days"))
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "max_connections" in body:
            mc = int(body["max_connections"] or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

@app.get("/api/domain")
async def get_custom_domain(_=Depends(require_auth)):
    async with CUSTOM_DOMAIN_LOCK:
        return {"domain": CUSTOM_DOMAIN}

@app.post("/api/domain")
async def set_custom_domain(request: Request, _=Depends(require_auth)):
    body = await request.json()
    domain = (body.get("domain") or "").strip().lower()
    if domain:
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        if not re.match(r'^[a-z0-9\-_.]+$', domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
    async with CUSTOM_DOMAIN_LOCK:
        global CUSTOM_DOMAIN
        CUSTOM_DOMAIN = domain
    return {"ok": True, "domain": CUSTOM_DOMAIN}

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Address must contain only English letters, numbers, and characters: - _ .")
    async with CUSTOM_ADDRESSES_LOCK:
        if address in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(address)
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            CUSTOM_ADDRESSES.pop(index)
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.get("/api/links/{uid}/sub")
async def get_subscription(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    vless_link = generate_vless_link(uid, remark=f"NyxRelay-{link['label']}")
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    used_mb = round(used / (1024 * 1024), 2)
    limit_mb = round(limit / (1024 * 1024), 2) if limit > 0 else 0
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    remaining_mb = round((limit - used) / (1024 * 1024), 2) if limit > 0 else 0
    import base64
    sub_content = f"""# NyxRelay Subscription
# Label: {link['label']}
# Used: {used_mb} MB / {limit_mb if limit > 0 else 'Unlimited'} MB
# Remaining: {remaining_mb if limit > 0 else 'Unlimited'} MB
# Usage: {pct}%
# Status: {'Active' if link['active'] else 'Disabled'}
# Expiry: {link.get('expiry', '')[:10] if link.get('expiry') else 'Unlimited'}
{vless_link}"""
    encoded = base64.b64encode(sub_content.encode()).decode()
    return {
        "subscription_url": f"{get_domain()}/api/links/{uid}/sub",
        "config": vless_link,
        "label": link["label"],
        "used_bytes": used,
        "limit_bytes": limit,
        "used_mb": used_mb,
        "limit_mb": limit_mb,
        "remaining_mb": remaining_mb,
        "usage_percent": pct,
        "active": link["active"],
        "sub_base64": encoded,
        "sub_text": sub_content,
    }

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
    if is_expired(link):
        raise HTTPException(status_code=403, detail="link expired")
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    sub_links = []
    server_link = generate_vless_link(uid, remark=f"NyxRelay-{link['label']}-Server")
    sub_links.append(server_link)
    for i, addr in enumerate(addresses):
        remark = f"NyxRelay-{link['label']}-IP{i+1}"
        vless_link = generate_vless_link(uid, remark=remark, address=addr)
        sub_links.append(vless_link)
    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode()).decode()
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=\"sub.txt\"",
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire={expiry_epoch(link)}"
    }
    return Response(content=encoded, headers=headers)

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if is_expired(link): return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        if not SERVICE_RUNNING:
            await websocket.close(code=1012, reason="service stopped"); return
        async with LINKS_LOCK:
            link_data = LINKS.get(uuid)
            if link_data is None or not link_data["active"]:
                await websocket.close(code=1008, reason="link not found or disabled"); return
            if is_expired(link_data):
                await websocket.close(code=1008, reason="link expired"); return
            max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = client_ip in link_ip_map.get(uuid, set())
            if not already_connected:
                current = count_connections_for_link(uuid)
                if current >= max_conn:
                    await websocket.close(code=1008, reason="connection limit reached"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)
        size = len(first_chunk)
        stats["total_bytes"] += size; stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload); await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid = info.get("uuid")
                ip = info.get("ip")
                if uid and ip:
                    has_other = any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values())
                    if not has_other:
                        remove_ip_from_link(uid, ip)

# ─── HTML Pages ────────────────────────────────────────────────────────────────

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NyxRelay - Welcome</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1b2a;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}
#login{background:#151f31;border-radius:2rem;padding:3rem 2rem 2.5rem;width:100%;max-width:380px;position:relative;animation:charge .5s ease both}
@keyframes charge{0%{transform:translateY(2rem);opacity:0}100%{transform:translateY(0);opacity:1}}
.setting-section{position:absolute;top:16px;right:16px}
.ant-btn-circle{border-radius:50%;width:38px;height:38px;padding:0;border:none;background:#1e8a7a;color:#fff;cursor:pointer;display:flex;align-items:center;justify-content:center}
.ant-btn-circle:hover{background:#00a896}
.title{font-size:2.2rem;font-weight:700;text-align:center;margin-bottom:2rem;color:#b0bec5;letter-spacing:1px}
.words-wrapper{display:inline-block;position:relative;text-align:center;width:100%}
.words-wrapper b{display:inline-block;position:absolute;left:0;top:0;width:100%;opacity:0}
.words-wrapper b.is-visible{position:relative;opacity:1;animation:zoom-in .8s cubic-bezier(.215,.61,.355,1) forwards}
.words-wrapper b.is-hidden{animation:zoom-out .4s cubic-bezier(.215,.61,.355,1) forwards}
@keyframes zoom-in{0%{opacity:0;transform:translateZ(100px)}100%{opacity:1;transform:translateZ(0)}}
@keyframes zoom-out{0%{opacity:1;transform:translateZ(0)}100%{opacity:0;transform:translateZ(-100px)}}
.headline{display:flex;justify-content:center;align-items:center}
.headline.zoom .words-wrapper{perspective:300px}
.fields{display:flex;flex-direction:column;gap:14px;margin-bottom:1.5rem}
.ant-input-affix-wrapper{display:flex;align-items:center;background:#1e2d42;border:1.5px solid #1e2d42;border-radius:30px;padding:0 16px;height:52px;transition:border-color .3s}
.ant-input-affix-wrapper:focus-within{border-color:#008771;box-shadow:0 0 0 2px rgba(0,135,113,.15)}
.ant-input-prefix{display:flex;align-items:center;margin-right:10px;color:#4a6080}
.ant-input{flex:1;background:transparent;border:none;outline:none;color:#fff;font-size:14px;height:100%;padding:0}
.ant-input::placeholder{color:#4a6080}
.ant-input-suffix{display:flex;align-items:center;color:#4a6080;cursor:pointer;padding-left:8px}
.ant-input-suffix:hover{color:#fff}
.wave-btn-bg{border-radius:30px;overflow:hidden;position:relative}
.wave-btn-bg-cl{background:linear-gradient(135deg,#007a68,#008771,#005565);background-size:200% 200%;transition:.3s}
.wave-btn-bg-cl:hover{background-position:right center}
.ant-btn-primary-login{font-size:15px;font-weight:600;color:#fff;background:transparent;border:none;height:50px;width:100%;cursor:pointer;letter-spacing:.5px}
.err-msg{color:#ef4444;text-align:center;font-size:13px;padding:8px;background:rgba(239,68,68,0.1);border-radius:8px;display:none;margin-top:8px}
.err-msg.show{display:block}
</style>
</head>
<body>
<div id="login">
  <div class="setting-section">
    <button class="ant-btn-circle" onclick="toggleTheme()">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
    </button>
  </div>
  <h2 class="title headline zoom"><span class="words-wrapper"><b class="is-visible">NyxRelay</b></span></h2>
  <form id="login-form">
    <div class="fields">
      <span class="ant-input-affix-wrapper">
        <span class="ant-input-prefix">
          <svg viewBox="64 64 896 896" width="1em" height="1em" fill="currentColor"><path d="M858.5 763.6a374 374 0 0 0-80.6-119.5 375.63 375.63 0 0 0-119.5-80.6c-.4-.2-.8-.3-1.2-.5C719.5 518 760 444.7 760 362c0-137-111-248-248-248S264 225 264 362c0 82.7 40.5 156 102.8 201.1-.4.2-.8.3-1.2.5-44.8 18.9-85 46-119.5 80.6a375.63 375.63 0 0 0-80.6 119.5A371.7 371.7 0 0 0 136 901.8a8 8 0 0 0 8 8.2h60c4.4 0 7.9-3.5 8-7.8 2-77.2 33-149.5 87.8-204.3 56.7-56.7 132-87.9 212.2-87.9s155.5 31.2 212.2 87.9C779 752.7 810 825 812 902.2c.1 4.4 3.6 7.8 8 7.8h60a8 8 0 0 0 8-8.2c-1-47.8-10.9-94.3-29.5-138.2zM512 534c-45.9 0-89.1-17.9-121.6-50.4S340 407.9 340 362c0-45.9 17.9-89.1 50.4-121.6S466.1 190 512 190s89.1 17.9 121.6 50.4S684 316.1 684 362c0 45.9-17.9 89.1-50.4 121.6S557.9 534 512 534z"/></svg>
        </span>
        <input placeholder="Username" type="text" name="username" autocomplete="username" autofocus class="ant-input" id="username" value="admin">
      </span>
      <span class="ant-input-affix-wrapper">
        <span class="ant-input-prefix">
          <svg viewBox="64 64 896 896" width="1em" height="1em" fill="currentColor"><path d="M832 464h-68V240c0-70.7-57.3-128-128-128H388c-70.7 0-128 57.3-128 128v224h-68c-17.7 0-32 14.3-32 32v384c0 17.7 14.3 32 32 32h640c17.7 0 32-14.3 32-32V496c0-17.7-14.3-32-32-32zM332 240c0-30.9 25.1-56 56-56h248c30.9 0 56 25.1 56 56v224H332V240zm460 600H232V536h560v304zM484 701v53c0 4.4 3.6 8 8 8h40c4.4 0 8-3.6 8-8v-53a48.01 48.01 0 1 0-56 0z"/></svg>
        </span>
        <input placeholder="Password" type="password" name="password" autocomplete="current-password" class="ant-input" id="password">
        <span class="ant-input-suffix" onclick="togglePassword()">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
        </span>
      </span>
    </div>
    <div class="err-msg" id="err-msg"></div>
    <div class="wave-btn-bg wave-btn-bg-cl">
      <button type="submit" class="ant-btn-primary-login">Log In</button>
    </div>
  </form>
</div>
<script>
let darkTheme = true;
function toggleTheme() {
  darkTheme = !darkTheme;
  document.body.style.background = darkTheme ? '#0d1b2a' : '#e8f5f2';
  document.getElementById('login').style.background = darkTheme ? '#151f31' : '#fff';
}
function togglePassword() {
  const input = document.getElementById('password');
  input.type = input.type === 'password' ? 'text' : 'password';
}
document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = document.getElementById('err-msg');
  err.classList.remove('show');
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      err.textContent = d.detail || 'Invalid username or password';
      err.classList.add('show');
      return;
    }
    window.location.href = '/dashboard';
  } catch(e) {
    err.textContent = 'Connection error';
    err.classList.add('show');
  }
});
</script>
</body>
</html>"""


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NyxRelay - Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a1222;color:rgba(255,255,255,0.75);min-height:100vh}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#2a2a2a;border-radius:3px}
.ant-layout{display:flex;height:100vh}
.ant-layout-has-sider{flex-direction:row}
.ant-layout-sider{background:#111929;height:100%;display:flex;flex-direction:column;border-right:1px solid #1a1a1a;position:fixed;left:0;top:0;bottom:0;width:200px;z-index:100;transition:transform .3s}
.ant-layout-sider-children{flex:1;display:flex;flex-direction:column;padding:8px;overflow-y:auto}
.brand-title{padding:14px 12px 10px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #1a1a1a;margin-bottom:6px}
.brand-title svg{flex-shrink:0}
.brand-title span{font-size:15px;font-weight:700;color:#fff;letter-spacing:-0.02em}
.brand-title .version{font-size:10px;color:#555;font-weight:400;margin-left:2px}
.ant-menu{list-style:none;padding:0;margin:0;background:transparent}
.ant-menu-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;color:#888;font-size:13px;cursor:pointer;transition:all .15s;border:none;background:none;width:100%;text-align:left;margin:1px 0}
.ant-menu-item:hover{background:rgba(0,135,113,0.08);color:#fff}
.ant-menu-item-selected{background:rgba(0,135,113,0.12);color:#008771;font-weight:600}
.nav-badge{margin-left:auto;background:#1a1a1a;color:#555;font-size:10px;padding:2px 7px;border-radius:8px;font-weight:600}
.nav-section{font-size:10px;font-weight:700;color:#444;text-transform:uppercase;letter-spacing:0.08em;padding:12px 12px 4px}
.ant-layout-sider-footer{padding:10px;border-top:1px solid #1a1a1a}
.logout-btn{width:100%;padding:7px;border:1px solid #1a1a1a;border-radius:7px;background:none;color:#555;font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px}
.logout-btn:hover{background:rgba(239,68,68,0.08);border-color:rgba(239,68,68,0.2);color:#ef4444}
.ant-layout-sider-trigger{height:44px;background:#111929;color:rgba(255,255,255,0.45);display:flex;align-items:center;justify-content:center;cursor:pointer;border-top:1px solid #1a1a1a;font-size:12px;gap:8px;transition:all .2s}
.ant-layout-sider-trigger:hover{color:#fff}
#content-layout{flex:1;margin-left:200px;overflow-y:auto;padding:20px 20px 48px}
.page{display:none;animation:pageIn .3s ease}
.page.active{display:block}
@keyframes pageIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.ant-card{background:#151f31;border:1px solid #1a1a1a;border-radius:12px;padding:16px;margin-bottom:12px}
.ant-card:hover{box-shadow:0 2px 8px rgba(0,0,0,.3)}
.ant-card-head{display:flex;align-items:center;justify-content:space-between;padding-bottom:12px;border-bottom:1px solid #1a1a1a;margin-bottom:12px}
.ant-card-head-title{font-size:14px;font-weight:600;color:rgba(255,255,255,0.85)}
.ant-card-extra{color:rgba(255,255,255,0.45);font-size:13px}
.ant-row{display:flex;flex-wrap:wrap;margin:-6px -8px}
.ant-col{padding:6px 8px;flex:0 0 auto}
.ant-col-12{width:50%}.ant-col-sm-12{width:50%}.ant-col-md-12{width:50%}.ant-col-sm-24{width:100%}.ant-col-md-6{width:25%}
.ant-statistic-title{font-size:11px;color:rgba(255,255,255,0.45);margin-bottom:4px}
.ant-statistic-content{font-size:16px;color:rgba(255,255,255,0.85);display:flex;align-items:center;gap:6px}
.ant-statistic-content-prefix{color:rgba(255,255,255,0.35)}
.ant-tag{display:inline-flex;align-items:center;padding:2px 10px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;margin:2px}
.ant-tag-green{background:rgba(0,135,113,0.15);color:#008771;border:1px solid rgba(0,135,113,0.2)}
.ant-tag-orange{background:rgba(255,160,49,0.15);color:#ffa031;border:1px solid rgba(255,160,49,0.2)}
.ant-tag-purple{background:rgba(217,136,205,0.15);color:#d988cd;border:1px solid rgba(217,136,205,0.2)}
.ant-tag-red{background:rgba(239,68,68,0.1);color:#ef4444;border:1px solid rgba(239,68,68,0.15)}
.ant-badge-status{display:inline-flex;align-items:center;gap:6px}
.ant-badge-status-dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.ant-badge-status-green{background:#22c55e}
.ant-badge-status-text{font-size:12px;color:rgba(255,255,255,0.75)}
.ant-badge-status-processing{animation:pulse 1.2s ease-in-out infinite}
@keyframes pulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.5);opacity:.4}}
.ant-btn{font-family:inherit;font-size:12px;font-weight:600;border-radius:8px;padding:7px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:all .15s}
.ant-btn-primary{background:#008771;color:#fff}
.ant-btn-primary:hover{background:#006b5a}
.ant-btn-secondary{background:#1a1a1a;color:#888;border:1px solid #2a2a2a}
.ant-btn-secondary:hover{border-color:#008771;color:#008771}
.ant-btn-danger{background:rgba(239,68,68,0.1);color:#ef4444;border:1px solid rgba(239,68,68,0.12)}
.ant-btn-danger:hover{background:rgba(239,68,68,0.2)}
.ant-btn-sm{padding:4px 10px;font-size:11px}
.sys-bar{height:6px;background:#1a1a1a;border-radius:3px;overflow:hidden;margin-top:8px}
.sys-bar-fill{height:100%;border-radius:3px;transition:width .5s}
.ant-table-wrapper{overflow-x:auto;margin-top:4px}
.ant-table{width:100%;border-collapse:collapse;font-size:13px}
.ant-table th{text-align:left;font-size:11px;font-weight:600;color:#555;padding:10px 12px;text-transform:uppercase;border-bottom:1px solid #1a1a1a;background:#111}
.ant-table td{padding:10px 12px;border-bottom:1px solid #1a1a1a;vertical-align:middle;color:#ccc}
.ant-table tr:last-child td{border-bottom:none}
.ant-table tbody tr:hover td{background:rgba(0,135,113,0.04)}
.toggle{width:34px;height:18px;border-radius:10px;background:#2a2a2a;position:relative;cursor:pointer;transition:all .3s;border:1px solid #333;flex-shrink:0}
.toggle.on{background:#22c55e;border-color:#22c55e;box-shadow:0 0 12px rgba(34,197,94,0.3)}
.toggle::after{content:'';position:absolute;width:12px;height:12px;border-radius:50%;background:#888;top:2px;left:2px;transition:all .3s}
.toggle.on::after{left:16px;background:#fff}
.usage-pill{display:flex;align-items:center;gap:8px;padding:2px 10px;border-radius:999px;background:#1a1a1a;font-size:11px;color:#888}
.usage-pill .used{color:#fff;font-weight:600}
.usage-pill .bar{flex:1;height:4px;background:#2a2a2a;border-radius:2px;min-width:50px}
.usage-pill .fill{height:100%;border-radius:2px;transition:width .3s}
.usage-pill .limit{color:#555}
.btn-copy{background:rgba(0,135,113,0.1);color:#008771;border:1px solid rgba(0,135,113,0.15);font-family:inherit;font-size:11px;font-weight:600;border-radius:8px;padding:4px 10px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;transition:all .15s}
.btn-copy:hover{background:#008771;color:#fff}
.btn-qr{background:rgba(34,197,94,0.1);color:#22c55e;border:1px solid rgba(34,197,94,0.15);font-family:inherit;font-size:11px;font-weight:600;border-radius:8px;padding:4px 10px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;transition:all .15s}
.btn-qr:hover{background:#22c55e;color:#fff}
.search-box{flex:1;min-width:160px;position:relative}
.search-box input{width:100%;padding:8px 12px 8px 32px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:8px;color:#fff;font-size:12px;outline:none;transition:all .2s;font-family:inherit}
.search-box input:focus{border-color:#008771}
.search-box svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:#555}
.filter-chips{display:flex;gap:3px;padding:3px 5px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:8px}
.chip{padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;color:#666;cursor:pointer;border:none;background:none;transition:all .2s;font-family:inherit}
.chip.active{background:#008771;color:#fff}
.chip:hover:not(.active){background:#2a2a2a;color:#fff}
.inbounds-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(20px);background:#151f31;color:#fff;border:1px solid #1a1a1a;border-radius:10px;padding:10px 20px;font-size:12px;font-weight:500;opacity:0;transition:all .3s;z-index:999;display:flex;align-items:center;gap:8px;box-shadow:0 8px 24px rgba(0,0,0,0.4)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.error{border-color:rgba(239,68,68,0.3);color:#ef4444}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(6px)}
.modal-overlay.show{display:flex}
.modal{background:#151f31;border:1px solid #1a1a1a;border-radius:16px;padding:24px;width:100%;max-width:440px;position:relative;box-shadow:0 20px 60px rgba(0,0,0,0.5)}
.modal-title{font-size:15px;font-weight:700;margin-bottom:16px;color:rgba(255,255,255,0.85)}
.modal-close{position:absolute;top:12px;right:14px;background:#1a1a1a;border:1px solid #2a2a2a;color:#666;width:26px;height:26px;border-radius:6px;cursor:pointer;font-size:14px;display:flex;align-items:center;justify-content:center;transition:all .2s}
.modal-close:hover{background:rgba(239,68,68,0.1);color:#ef4444}
.form-group{display:flex;flex-direction:column;gap:5px;margin-bottom:12px}
.form-label{font-size:11px;font-weight:600;color:#888;text-transform:uppercase;letter-spacing:0.04em}
.form-input,.form-select{padding:8px 12px;border-radius:8px;border:1px solid #2a2a2a;font-family:inherit;font-size:13px;outline:none;color:#fff;background:#1a1a1a;transition:all .2s;width:100%}
.form-input:focus,.form-select:focus{border-color:#008771;box-shadow:0 0 0 3px rgba(0,135,113,0.1)}
.form-select option{background:#1a1a1a;color:#fff}
.form-row{display:flex;gap:8px}
.form-row .form-group{margin-bottom:0;flex:1}
.qr-box{text-align:center;padding:20px;background:#111;border-radius:12px;margin-top:12px}
.qr-box img{max-width:200px;border-radius:8px}
.status-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid #1a1a1a}
.status-row:last-child{border-bottom:none}
.status-key{font-size:12px;color:#888;display:flex;align-items:center;gap:8px}
.status-val{font-size:12px;color:#ccc;font-weight:600}
.empty-state{text-align:center;padding:40px;color:#555}
.mobile-header{display:none;position:fixed;top:0;left:0;right:0;height:44px;background:#111929;border-bottom:1px solid #1a1a1a;z-index:90;align-items:center;justify-content:space-between;padding:0 14px}
.menu-toggle{width:32px;height:32px;border-radius:8px;border:1px solid #1a1a1a;background:#151f31;color:#888;display:flex;align-items:center;justify-content:center;cursor:pointer}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:99}
.sidebar-overlay.show{display:block}
@media(max-width:768px){
  .ant-layout-sider{transform:translateX(-100%);width:200px;z-index:200}
  .ant-layout-sider.open{transform:translateX(0);box-shadow:4px 0 20px rgba(0,0,0,0.5)}
  #content-layout{margin-left:0;padding-top:56px;padding-left:12px;padding-right:12px}
  .mobile-header{display:flex}
  .ant-col-md-12{width:100%}
  .ant-col-md-6{width:50%}
}
@media(max-width:480px){.ant-col-md-6{width:100%}}
/* ── Overview (NyxRelay) ── */
.gauge-row{display:flex;gap:2px;align-items:flex-start}
.gauge{flex:1;min-width:0;text-align:center;padding:2px 0}
.gauge-svg{width:100%;max-width:118px;height:auto}
.gauge-pct{font-size:16px;font-weight:700;fill:rgba(255,255,255,0.85)}
.gauge-arc{transition:stroke-dasharray .6s ease}
.gauge-label{margin-top:2px;font-size:11px;line-height:1.35}
.gl-title{color:rgba(255,255,255,0.78);font-weight:600;display:block}
.gl-sub{color:rgba(255,255,255,0.45);display:block;font-size:10.5px}
.split-row{display:flex;align-items:stretch}
.split-col{flex:1;display:flex;align-items:center;justify-content:center;gap:7px;padding:11px 6px;background:none;border:none;color:rgba(255,255,255,0.7);font-family:inherit;font-size:13px;font-weight:500;cursor:pointer;transition:all .15s}
.split-col + .split-col{border-left:1px solid #1a2536}
button.split-col:hover{color:#2bd4a0;background:rgba(43,212,160,0.06)}
.split-col svg{flex-shrink:0;opacity:.85}
.tag-row{display:flex;flex-wrap:wrap;gap:6px;padding-top:2px}
.tag-row .ant-tag{font-size:11px;text-transform:none;font-weight:600;padding:3px 11px;border-radius:6px}
.update-btn{display:inline-flex;align-items:center;gap:6px;font-family:inherit;font-size:11px;font-weight:600;color:#ffa031;background:rgba(255,160,49,0.1);border:1px solid rgba(255,160,49,0.25);border-radius:7px;padding:5px 10px;cursor:pointer;transition:all .15s}
.update-btn:hover{background:rgba(255,160,49,0.18)}
.eye-btn{background:none;border:none;color:rgba(255,255,255,0.45);cursor:pointer;padding:2px;display:flex;transition:color .15s}
.eye-btn:hover{color:#fff}
.ip-val{font-family:monospace;font-size:13px;color:rgba(255,255,255,0.85);transition:filter .2s}
.ip-val.ip-hidden{filter:blur(6px);user-select:none}
.spd-up{color:#2bd4a0}.spd-down{color:#3b9dff}
.data-stat{display:flex;align-items:center;gap:6px}
.data-stat svg{color:rgba(255,255,255,0.4)}
.log-box{background:#0b1220;border:1px solid #1a2536;border-radius:8px;padding:12px;font-family:monospace;font-size:11.5px;color:#9fb3c8;max-height:50vh;overflow:auto;white-space:pre-wrap;word-break:break-word;line-height:1.6}
</style>
</head>
<body>

<div class="toast" id="toast"></div>

<div class="mobile-header">
  <span style="font-weight:700;font-size:13px;color:#fff">NyxRelay</span>
  <button class="menu-toggle" onclick="toggleSidebar()">&#9776;</button>
</div>
<div class="sidebar-overlay" id="sidebar-overlay" onclick="closeSidebar()"></div>

<aside class="ant-layout-sider" id="sidebar">
  <div class="ant-layout-sider-children">
    <div class="brand-title">
      <svg width="26" height="26" viewBox="0 0 56 56" fill="none">
        <rect width="56" height="56" rx="14" fill="url(#lg)"/>
        <circle cx="28" cy="28" r="14" stroke="#fff" stroke-width="1.5" opacity="0.3"/>
        <circle cx="28" cy="18" r="3.5" fill="#fff"/>
        <circle cx="19" cy="33" r="3.5" fill="#fff"/>
        <circle cx="37" cy="33" r="3.5" fill="#fff"/>
        <line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <circle cx="28" cy="28" r="2" fill="#fff" opacity="0.9"/>
        <defs><linearGradient id="lg" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#008771"/><stop offset="1" stop-color="#005565"/></linearGradient></defs>
      </svg>
      <span>NyxRelay <span class="version">v1.0</span></span>
    </div>
    <div class="nav-section">Main</div>
    <ul class="ant-menu">
      <li class="ant-menu-item ant-menu-item-selected" onclick="switchPage('overview',this)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        <span>Overview</span>
      </li>
      <li class="ant-menu-item" onclick="switchPage('inbounds',this)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
        <span>Inbounds</span>
        <span class="nav-badge" id="links-badge">0</span>
      </li>
      <li class="ant-menu-item" onclick="switchPage('cleanip',this)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
        <span>Clean IP</span>
      </li>
      <li class="ant-menu-item" onclick="switchPage('domain',this)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
        <span>Domain</span>
      </li>
    </ul>
    <div class="nav-section">System</div>
    <ul class="ant-menu">
      <li class="ant-menu-item" onclick="switchPage('settings',this)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        <span>Settings</span>
      </li>
    </ul>
  </div>
  <div class="ant-layout-sider-footer">
    <button class="logout-btn" onclick="doLogout()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      Log Out
    </button>
  </div>
  <div class="ant-layout-sider-trigger" onclick="toggleSidebar()">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 18l-6-6 6-6"/></svg>
    <span style="font-size:11px">Collapse</span>
  </div>
</aside>

<section id="content-layout">

  <!-- ── OVERVIEW ── -->
  <div class="page active" id="page-overview">

    <!-- Gauges -->
    <div class="ant-card">
      <svg width="0" height="0" style="position:absolute"><defs>
        <linearGradient id="gaugeGrad" x1="0" y1="1" x2="1" y2="0">
          <stop offset="0" stop-color="#0e9f6e"/><stop offset="1" stop-color="#2bd4a0"/>
        </linearGradient></defs></svg>
      <div class="gauge-row">
        <div class="gauge">
          <svg viewBox="0 0 100 100" class="gauge-svg">
            <path class="gauge-track" d="M 50 50 m 0 -42 a 42 42 0 1 1 0 84 a 42 42 0 1 1 0 -84"
                  fill="none" stroke="#1f2a3d" stroke-width="7"
                  stroke-dasharray="197.9 263.9" transform="rotate(135 50 50)" stroke-linecap="round"/>
            <path id="cpu-arc" class="gauge-arc" d="M 50 50 m 0 -42 a 42 42 0 1 1 0 84 a 42 42 0 1 1 0 -84"
                  fill="none" stroke="url(#gaugeGrad)" stroke-width="7"
                  stroke-dasharray="0 263.9" transform="rotate(135 50 50)" stroke-linecap="round"/>
            <text id="cpu-text" x="50" y="54" text-anchor="middle" class="gauge-pct">0%</text>
          </svg>
          <div class="gauge-label"><span class="gl-title">CPU: <span id="cpu-cores">--</span></span><span id="cpu-label" class="gl-sub"></span></div>
        </div>
        <div class="gauge">
          <svg viewBox="0 0 100 100" class="gauge-svg">
            <path class="gauge-track" d="M 50 50 m 0 -42 a 42 42 0 1 1 0 84 a 42 42 0 1 1 0 -84"
                  fill="none" stroke="#1f2a3d" stroke-width="7"
                  stroke-dasharray="197.9 263.9" transform="rotate(135 50 50)" stroke-linecap="round"/>
            <path id="ram-arc" class="gauge-arc" d="M 50 50 m 0 -42 a 42 42 0 1 1 0 84 a 42 42 0 1 1 0 -84"
                  fill="none" stroke="url(#gaugeGrad)" stroke-width="7"
                  stroke-dasharray="0 263.9" transform="rotate(135 50 50)" stroke-linecap="round"/>
            <text id="ram-text" x="50" y="54" text-anchor="middle" class="gauge-pct">0%</text>
          </svg>
          <div class="gauge-label"><span class="gl-title">RAM:</span><span id="ram-label" class="gl-sub"></span></div>
        </div>
        <div class="gauge">
          <svg viewBox="0 0 100 100" class="gauge-svg">
            <path class="gauge-track" d="M 50 50 m 0 -42 a 42 42 0 1 1 0 84 a 42 42 0 1 1 0 -84"
                  fill="none" stroke="#1f2a3d" stroke-width="7"
                  stroke-dasharray="197.9 263.9" transform="rotate(135 50 50)" stroke-linecap="round"/>
            <path id="swap-arc" class="gauge-arc" d="M 50 50 m 0 -42 a 42 42 0 1 1 0 84 a 42 42 0 1 1 0 -84"
                  fill="none" stroke="url(#gaugeGrad)" stroke-width="7"
                  stroke-dasharray="0 263.9" transform="rotate(135 50 50)" stroke-linecap="round"/>
            <text id="swap-text" x="50" y="54" text-anchor="middle" class="gauge-pct">0%</text>
          </svg>
          <div class="gauge-label"><span class="gl-title">Swap:</span><span id="swap-label" class="gl-sub"></span></div>
        </div>
        <div class="gauge">
          <svg viewBox="0 0 100 100" class="gauge-svg">
            <path class="gauge-track" d="M 50 50 m 0 -42 a 42 42 0 1 1 0 84 a 42 42 0 1 1 0 -84"
                  fill="none" stroke="#1f2a3d" stroke-width="7"
                  stroke-dasharray="197.9 263.9" transform="rotate(135 50 50)" stroke-linecap="round"/>
            <path id="storage-arc" class="gauge-arc" d="M 50 50 m 0 -42 a 42 42 0 1 1 0 84 a 42 42 0 1 1 0 -84"
                  fill="none" stroke="url(#gaugeGrad)" stroke-width="7"
                  stroke-dasharray="0 263.9" transform="rotate(135 50 50)" stroke-linecap="round"/>
            <text id="storage-text" x="50" y="54" text-anchor="middle" class="gauge-pct">0%</text>
          </svg>
          <div class="gauge-label"><span class="gl-title">Storage:</span><span id="storage-label" class="gl-sub"></span></div>
        </div>
      </div>
    </div>

    <!-- Xray (core) -->
    <div class="ant-card">
      <div class="ant-card-head">
        <div class="ant-card-head-title">Xray</div>
        <div class="ant-card-extra">
          <span class="ant-badge-status" id="xray-badge">
            <span class="ant-badge-status-dot ant-badge-status-green ant-badge-status-processing"></span>
            <span class="ant-badge-status-text" id="xray-status">Running</span>
          </span>
        </div>
      </div>
      <div class="split-row">
        <button class="split-col" onclick="stopService()">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/></svg>
          <span id="xray-action-1">Stop</span>
        </button>
        <button class="split-col" onclick="restartService()">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>
          <span>Restart</span>
        </button>
        <div class="split-col" style="cursor:default">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3"/></svg>
          <span id="core-version">{CORE}</span>
        </div>
      </div>
    </div>

    <!-- Manage -->
    <div class="ant-card">
      <div class="ant-card-head"><div class="ant-card-head-title">Manage</div></div>
      <div class="split-row">
        <button class="split-col" onclick="openLogs()">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
          <span>Logs</span>
        </button>
        <button class="split-col" onclick="openConfig()">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>
          <span>Config</span>
        </button>
        <button class="split-col" onclick="downloadBackup()">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
          <span>Backup</span>
        </button>
      </div>
    </div>

    <!-- NyxRelay -->
    <div class="ant-card">
      <div class="ant-card-head">
        <div class="ant-card-head-title">NyxRelay</div>
        <button class="update-btn" onclick="checkUpdate()">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 01-9 9c-2.5 0-4.78-1-6.43-2.6L3 16"/><path d="M3 12a9 9 0 019-9c2.5 0 4.78 1 6.43 2.6L21 8"/><polyline points="21 3 21 8 16 8"/><polyline points="3 21 3 16 8 16"/></svg>
          <span id="panel-version-btn">{PANEL}</span> Update Panel
        </button>
      </div>
      <div class="tag-row">
        <span class="ant-tag ant-tag-green" id="panel-version-tag">{PANEL}</span>
        <span class="ant-tag ant-tag-green" id="tg-tag">@NyxRelay</span>
        <span class="ant-tag ant-tag-purple">Documentation</span>
      </div>
    </div>

    <!-- Uptime -->
    <div class="ant-card">
      <div class="ant-card-head"><div class="ant-card-head-title">Uptime</div></div>
      <div class="tag-row">
        <span class="ant-tag ant-tag-green">Xray: <span id="xray-uptime">--</span></span>
        <span class="ant-tag ant-tag-green">OS: <span id="os-uptime">--</span></span>
      </div>
    </div>

    <!-- System Load -->
    <div class="ant-card">
      <div class="ant-card-head"><div class="ant-card-head-title">System Load</div></div>
      <div class="tag-row"><span class="ant-tag ant-tag-green" id="system-load">--</span></div>
    </div>

    <!-- Usage -->
    <div class="ant-card">
      <div class="ant-card-head"><div class="ant-card-head-title">Usage</div></div>
      <div class="tag-row">
        <span class="ant-tag ant-tag-green">RAM: <span id="app-ram">--</span></span>
        <span class="ant-tag ant-tag-green">Threads: <span id="threads">--</span></span>
      </div>
    </div>

    <!-- Overall Speed -->
    <div class="ant-card">
      <div class="ant-card-head"><div class="ant-card-head-title">Overall Speed</div></div>
      <div class="ant-row">
        <div class="ant-col ant-col-12">
          <div class="ant-statistic-title">Upload</div>
          <div class="ant-statistic-content"><span class="spd-up">&#8593;</span> <span id="upload-speed">-- B/s</span></div>
        </div>
        <div class="ant-col ant-col-12">
          <div class="ant-statistic-title">Download</div>
          <div class="ant-statistic-content"><span class="spd-down">&#8595;</span> <span id="download-speed">-- B/s</span></div>
        </div>
      </div>
    </div>

    <!-- Total Data -->
    <div class="ant-card">
      <div class="ant-card-head"><div class="ant-card-head-title">Total Data</div></div>
      <div class="ant-row">
        <div class="ant-col ant-col-12">
          <div class="ant-statistic-title">Sent</div>
          <div class="ant-statistic-content data-stat"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10h-1.26A8 8 0 109 20h9a5 5 0 000-10z"/><polyline points="8 12 12 8 16 12"/><line x1="12" y1="16" x2="12" y2="8"/></svg> <span id="total-sent">--</span></div>
        </div>
        <div class="ant-col ant-col-12">
          <div class="ant-statistic-title">Received</div>
          <div class="ant-statistic-content data-stat"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10h-1.26A8 8 0 109 20h9a5 5 0 000-10z"/><polyline points="8 12 12 16 16 12"/><line x1="12" y1="8" x2="12" y2="16"/></svg> <span id="total-received">--</span></div>
        </div>
      </div>
    </div>

    <!-- IP Addresses -->
    <div class="ant-card">
      <div class="ant-card-head">
        <div class="ant-card-head-title">IP Addresses</div>
        <button class="eye-btn" id="ip-eye" onclick="toggleIps()" title="Show / hide">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
        </button>
      </div>
      <div class="ant-row">
        <div class="ant-col ant-col-12">
          <div class="ant-statistic-title">IPv4</div>
          <div class="ant-statistic-content"><span id="ipv4" class="ip-val ip-hidden">--</span></div>
        </div>
        <div class="ant-col ant-col-12">
          <div class="ant-statistic-title">IPv6</div>
          <div class="ant-statistic-content"><span id="ipv6" class="ip-val ip-hidden" style="font-size:11px;word-break:break-all">--</span></div>
        </div>
      </div>
    </div>

    <!-- Connection Stats -->
    <div class="ant-card">
      <div class="ant-card-head"><div class="ant-card-head-title">Connection Stats</div></div>
      <div class="ant-row">
        <div class="ant-col ant-col-12">
          <div class="ant-statistic-title">TCP</div>
          <div class="ant-statistic-content">&#8644; <span id="tcp-conn">--</span></div>
        </div>
        <div class="ant-col ant-col-12">
          <div class="ant-statistic-title">UDP</div>
          <div class="ant-statistic-content">&#8644; <span id="udp-conn">--</span></div>
        </div>
      </div>
    </div>

  </div>

  <!-- ── INBOUNDS ── -->
  <div class="page" id="page-inbounds">
    <!-- Stats row -->
    <div class="ant-row" style="margin:-6px -8px;margin-bottom:4px">
      <div class="ant-col ant-col-md-6 ant-col-sm-12"><div class="ant-card"><div class="ant-statistic"><div class="ant-statistic-title">Sent / Received</div><div class="ant-statistic-content" style="font-size:12px"><span id="ib-sent-recv">-- / --</span></div></div></div></div>
      <div class="ant-col ant-col-md-6 ant-col-sm-12"><div class="ant-card"><div class="ant-statistic"><div class="ant-statistic-title">Proxy Traffic</div><div class="ant-statistic-content" style="font-size:14px"><span id="ib-proxy-traffic">-- MB</span></div></div></div></div>
      <div class="ant-col ant-col-md-6 ant-col-sm-12"><div class="ant-card"><div class="ant-statistic"><div class="ant-statistic-title">Total Inbounds</div><div class="ant-statistic-content" style="font-size:18px"><span id="ib-total">0</span></div></div></div></div>
      <div class="ant-col ant-col-md-6 ant-col-sm-12"><div class="ant-card"><div class="ant-statistic"><div class="ant-statistic-title">Active Clients</div><div class="ant-statistic-content" style="font-size:18px"><span id="ib-clients">0</span></div></div></div></div>
    </div>

    <div class="ant-card" style="padding:0;overflow:hidden">
      <div class="ant-card-head" style="padding:14px 16px">
        <div class="ant-card-head-title">
          <div style="display:flex;align-items:center;gap:8px">
            <button class="ant-btn ant-btn-primary" onclick="showAddModal()">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
              Add Inbound
            </button>
            <button class="ant-btn ant-btn-secondary" onclick="loadInbounds()">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>
            </button>
          </div>
        </div>
      </div>
      <div style="padding:0 16px 8px">
        <div class="inbounds-toolbar">
          <div class="search-box">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input id="inbound-search" placeholder="Search by name..." oninput="filterInbounds()">
          </div>
          <div class="filter-chips">
            <button class="chip active" onclick="setFilter('all',this)">All</button>
            <button class="chip" onclick="setFilter('active',this)">Active</button>
            <button class="chip" onclick="setFilter('disabled',this)">Disabled</button>
          </div>
        </div>
      </div>
      <div class="ant-table-wrapper" style="padding:0 8px 8px">
        <table class="ant-table">
          <thead><tr>
            <th style="width:36px">#</th>
            <th>Remark</th>
            <th style="width:64px">Type</th>
            <th>Traffic</th>
            <th style="width:72px">IPs</th>
            <th style="width:60px">Status</th>
            <th style="width:120px">Actions</th>
          </tr></thead>
          <tbody id="inbounds-tbody"><tr><td colspan="7" style="text-align:center;padding:32px;color:#555">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── CLEAN IP ── -->
  <div class="page" id="page-cleanip">
    <div class="ant-card" style="max-width:520px">
      <div class="ant-card-head">
        <div class="ant-card-head-title">Clean IP / Addresses</div>
        <button class="ant-btn ant-btn-primary ant-btn-sm" onclick="showAddAddressModal()">+ Add</button>
      </div>
      <div style="font-size:11px;color:#555;margin-bottom:10px">IPs and domains for subscription configs. Default: www.speedtest.net</div>
      <div id="address-list"></div>
    </div>
  </div>

  <!-- ── DOMAIN ── -->
  <div class="page" id="page-domain">
    <div class="ant-card" style="max-width:480px">
      <div class="ant-card-head"><div class="ant-card-head-title">Custom Domain</div></div>
      <div class="status-row">
        <span class="status-key">Render Domain</span>
        <span class="status-val" id="render-domain" style="font-family:monospace;font-size:11px">--</span>
      </div>
      <div class="status-row">
        <span class="status-key">Custom Domain</span>
        <span class="status-val" style="display:flex;align-items:center;gap:8px">
          <span id="domain-value" style="font-family:monospace;font-size:11px">None set</span>
          <button class="ant-btn ant-btn-danger ant-btn-sm" id="domain-clear-btn" onclick="clearDomain()" style="display:none">Clear</button>
        </span>
      </div>
      <div class="form-group" style="margin-top:14px">
        <label class="form-label">Set New Domain</label>
        <div style="display:flex;gap:8px">
          <input class="form-input" id="domain-input" placeholder="example.com" style="flex:1">
          <button class="ant-btn ant-btn-primary" onclick="saveDomain()">Save</button>
        </div>
      </div>
      <div style="padding:10px;background:rgba(0,135,113,0.06);border:1px solid rgba(0,135,113,0.15);border-radius:8px;font-size:11px;color:#888;line-height:1.6;margin-top:4px">
        Set a custom domain to use in VLESS configs instead of the default Render/HuggingFace domain. Point your domain via CNAME or A record to this service.
      </div>
    </div>
  </div>

  <!-- ── SETTINGS ── -->
  <div class="page" id="page-settings">
    <div class="ant-card" style="max-width:440px">
      <div class="ant-card-head"><div class="ant-card-head-title">Change Password</div></div>
      <div class="form-group">
        <label class="form-label">Current Password</label>
        <input class="form-input" type="password" id="cur-pw" placeholder="Current password">
      </div>
      <div class="form-group">
        <label class="form-label">New Password</label>
        <input class="form-input" type="password" id="new-pw" placeholder="Min 4 characters">
      </div>
      <div class="form-group">
        <label class="form-label">Confirm Password</label>
        <input class="form-input" type="password" id="confirm-pw" placeholder="Repeat new password">
      </div>
      <button class="ant-btn ant-btn-primary" onclick="changePassword()" style="width:100%;justify-content:center;margin-top:4px">Update Password</button>
    </div>
  </div>

</section>

<!-- Add Inbound Modal -->
<div class="modal-overlay" id="add-modal" onclick="if(event.target===this)closeModal('add-modal')">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('add-modal')">×</button>
    <div class="modal-title">Add Inbound</div>
    <div class="form-group">
      <label class="form-label">Remark / Name</label>
      <input class="form-input" id="new-label" placeholder="e.g. User1">
    </div>
    <div class="form-row">
      <div class="form-group">
        <label class="form-label">Traffic Limit</label>
        <input class="form-input" id="new-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited">
      </div>
      <div class="form-group" style="max-width:90px">
        <label class="form-label">Unit</label>
        <select class="form-select" id="new-unit"><option value="GB">GB</option><option value="MB">MB</option></select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Max IPs (0 = Unlimited)</label>
      <input class="form-input" id="new-maxconn" type="number" min="0" step="1" placeholder="0">
    </div>
    <div class="form-group">
      <label class="form-label">Expiry Days (0 = Never)</label>
      <input class="form-input" id="new-expiry" type="number" min="0" step="1" placeholder="0">
    </div>
    <button class="ant-btn ant-btn-primary" onclick="createInbound()" style="width:100%;justify-content:center;margin-top:8px">Create</button>
  </div>
</div>

<!-- Edit Inbound Modal -->
<div class="modal-overlay" id="edit-modal" onclick="if(event.target===this)closeModal('edit-modal')">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('edit-modal')">×</button>
    <div class="modal-title" id="edit-title">Edit Inbound</div>
    <input type="hidden" id="edit-uid">
    <div class="form-group">
      <label class="form-label">Name (read-only)</label>
      <input class="form-input" id="edit-name" readonly style="opacity:0.5;cursor:not-allowed">
    </div>
    <div class="form-row">
      <div class="form-group">
        <label class="form-label">Traffic Limit</label>
        <input class="form-input" id="edit-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited">
      </div>
      <div class="form-group" style="max-width:90px">
        <label class="form-label">Unit</label>
        <select class="form-select" id="edit-unit"><option value="GB">GB</option><option value="MB">MB</option></select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Max IPs</label>
      <input class="form-input" id="edit-maxconn" type="number" min="0" step="1" placeholder="0 = Unlimited">
    </div>
    <div style="display:flex;gap:8px;margin-top:12px">
      <button class="ant-btn ant-btn-primary" onclick="saveEdit()" style="flex:1;justify-content:center">Save</button>
      <button class="ant-btn ant-btn-danger" onclick="resetTraffic()">Reset Traffic</button>
    </div>
  </div>
</div>

<!-- QR Modal -->
<div class="modal-overlay" id="qr-modal" onclick="if(event.target===this)closeModal('qr-modal')">
  <div class="modal" style="max-width:320px">
    <button class="modal-close" onclick="closeModal('qr-modal')">×</button>
    <div class="modal-title">QR Code</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR Code" style="max-width:100%;border-radius:8px"></div>
    <div style="display:flex;gap:8px;margin-top:14px">
      <button class="ant-btn ant-btn-primary" onclick="downloadQR()" style="flex:1;justify-content:center">Download</button>
      <button class="ant-btn ant-btn-secondary" onclick="closeModal('qr-modal')" style="flex:1;justify-content:center">Close</button>
    </div>
  </div>
</div>

<!-- Add Address Modal -->
<div class="modal-overlay" id="add-address-modal" onclick="if(event.target===this)closeModal('add-address-modal')">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('add-address-modal')">×</button>
    <div class="modal-title">Add Clean IP / Domain</div>
    <div class="form-group">
      <label class="form-label">IPs or Domains (one per line)</label>
      <textarea class="form-input" id="new-address" rows="5" placeholder="8.8.8.8&#10;example.com&#10;1.0.0.1" style="resize:vertical;font-family:monospace"></textarea>
    </div>
    <button class="ant-btn ant-btn-primary" onclick="addAddresses()" style="width:100%;justify-content:center;margin-top:8px">Add All</button>
  </div>
</div>

<!-- Logs Modal -->
<div class="modal-overlay" id="logs-modal" onclick="if(event.target===this)closeModal('logs-modal')">
  <div class="modal" style="max-width:560px">
    <button class="modal-close" onclick="closeModal('logs-modal')">×</button>
    <div class="modal-title">Logs</div>
    <div class="log-box" id="logs-box">Loading...</div>
    <div style="display:flex;gap:8px;margin-top:14px">
      <button class="ant-btn ant-btn-secondary" onclick="openLogs()" style="flex:1;justify-content:center">Refresh</button>
      <button class="ant-btn ant-btn-secondary" onclick="closeModal('logs-modal')" style="flex:1;justify-content:center">Close</button>
    </div>
  </div>
</div>

<!-- Config Modal -->
<div class="modal-overlay" id="config-modal" onclick="if(event.target===this)closeModal('config-modal')">
  <div class="modal" style="max-width:560px">
    <button class="modal-close" onclick="closeModal('config-modal')">×</button>
    <div class="modal-title">Config</div>
    <div class="log-box" id="config-box">Loading...</div>
    <div style="display:flex;gap:8px;margin-top:14px">
      <button class="ant-btn ant-btn-secondary" onclick="closeModal('config-modal')" style="flex:1;justify-content:center">Close</button>
    </div>
  </div>
</div>

<script>
let allLinks = [];
let currentFilter = 'all';
let apiStats = {};

// ── Navigation ──────────────────────────────────────────────
function switchPage(id, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  document.querySelectorAll('.ant-menu-item').forEach(n => n.classList.remove('ant-menu-item-selected'));
  if (el) el.classList.add('ant-menu-item-selected');
  closeSidebar();
  if (id === 'inbounds') loadInbounds();
  if (id === 'cleanip') loadAddresses();
  if (id === 'domain') loadDomain();
}

function toggleSidebar() {
  const s = document.getElementById('sidebar');
  const ov = document.getElementById('sidebar-overlay');
  s.classList.toggle('open');
  ov.classList.toggle('show');
}
function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('show');
}

function closeModal(id) { document.getElementById(id).classList.remove('show'); }
function showAddModal() { document.getElementById('add-modal').classList.add('show'); }

function toast(msg, err=false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast' + (err ? ' error' : '') + ' show';
  setTimeout(() => t.classList.remove('show'), 3000);
}

function esc(s) { return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function fmtBytes(b) {
  if (!b || b === 0) return '0 B';
  if (b >= 1073741824) return (b/1073741824).toFixed(2)+' GB';
  if (b >= 1048576) return (b/1048576).toFixed(2)+' MB';
  if (b >= 1024) return (b/1024).toFixed(1)+' KB';
  return b+' B';
}
function fmtLimit(b) {
  if (!b || b === 0) return 'Unlimited';
  const gb = b/1073741824;
  return (gb%1===0?gb.toFixed(0):gb.toFixed(1))+' GB';
}

// ── Stats ────────────────────────────────────────────────────
let ipsVisible = false;

function setGauge(prefix, pct){
  pct = Math.max(0, Math.min(100, pct||0));
  const FULL = 197.9; // length of the 270deg track
  const arc = document.getElementById(prefix+'-arc');
  const txt = document.getElementById(prefix+'-text');
  if (arc) arc.setAttribute('stroke-dasharray', (pct/100*FULL).toFixed(1)+' 263.9');
  if (txt) txt.textContent = pct.toFixed(2)+'%';
}

async function loadStats() {
  try {
    const r = await fetch('/api/stats');
    if (!r.ok) throw new Error();
    apiStats = await r.json();

    // Gauges
    setGauge('cpu', apiStats.cpuUsage||0);
    setGauge('ram', apiStats.ramUsage||0);
    setGauge('swap', apiStats.swapUsage||0);
    setGauge('storage', apiStats.storageUsage||0);

    const cores = apiStats.cpuCores||1;
    document.getElementById('cpu-cores').textContent = cores + ' Core' + (cores>1?'s':'');
    document.getElementById('ram-label').textContent = (apiStats.ramUsed||'')+' / '+(apiStats.ramTotal||'');
    document.getElementById('swap-label').textContent = (apiStats.swapUsed||'0 B')+' / '+(apiStats.swapTotal||'0 B');
    document.getElementById('storage-label').textContent = (apiStats.storageUsed||'')+' / '+(apiStats.storageTotal||'');

    // Xray status
    const running = apiStats.xrayRunning !== false;
    const dot = document.querySelector('#xray-badge .ant-badge-status-dot');
    document.getElementById('xray-status').textContent = running ? 'Running' : 'Stopped';
    document.getElementById('xray-action-1').textContent = running ? 'Stop' : 'Start';
    if (dot) {
      dot.classList.toggle('ant-badge-status-green', running);
      dot.classList.toggle('ant-badge-status-processing', running);
      dot.style.background = running ? '' : '#ef4444';
    }
    document.getElementById('core-version').textContent = apiStats.coreVersion || '--';
    const pv = apiStats.panelVersion || '--';
    document.getElementById('panel-version-btn').textContent = pv;
    document.getElementById('panel-version-tag').textContent = pv;
    if (apiStats.telegram) document.getElementById('tg-tag').textContent = apiStats.telegram;

    // Uptime / load / usage
    document.getElementById('xray-uptime').textContent = apiStats.xrayUptime || '--';
    document.getElementById('os-uptime').textContent = apiStats.uptime || '--';
    document.getElementById('system-load').textContent = apiStats.systemLoad || '--';
    document.getElementById('app-ram').textContent = apiStats.appRam || '--';
    document.getElementById('threads').textContent = apiStats.threads ?? '--';

    // Speed / data
    document.getElementById('upload-speed').textContent = apiStats.uploadSpeed || '-- B/s';
    document.getElementById('download-speed').textContent = apiStats.downloadSpeed || '-- B/s';
    document.getElementById('total-sent').textContent = apiStats.totalSent || '--';
    document.getElementById('total-received').textContent = apiStats.totalReceived || '--';

    // IPs
    document.getElementById('ipv4').textContent = apiStats.ipv4 || 'N/A';
    document.getElementById('ipv6').textContent = apiStats.ipv6 || 'N/A';

    // Connection stats
    document.getElementById('tcp-conn').textContent = apiStats.tcpConnections ?? '--';
    document.getElementById('udp-conn').textContent = apiStats.udpConnections ?? '--';

    // sidebar badge
    const lb = document.getElementById('links-badge');
    if (lb) lb.textContent = apiStats.linksCount || 0;

    // inbounds page mirrors
    if (document.getElementById('ib-proxy-traffic')) document.getElementById('ib-proxy-traffic').textContent = (apiStats.totalTrafficMb||0).toFixed(2)+' MB';
    if (document.getElementById('ib-total')) document.getElementById('ib-total').textContent = apiStats.linksCount || 0;
    if (document.getElementById('ib-sent-recv')) document.getElementById('ib-sent-recv').textContent = (apiStats.totalSent||'--')+' / '+(apiStats.totalReceived||'--');
    const rd = document.getElementById('render-domain');
    if (rd) rd.textContent = apiStats.domain || '--';
  } catch(e) {}
}

function toggleIps(){
  ipsVisible = !ipsVisible;
  document.querySelectorAll('.ip-val').forEach(el=>el.classList.toggle('ip-hidden', !ipsVisible));
}

async function stopService(){
  const running = apiStats.xrayRunning !== false;
  if (running){
    if(!confirm('Stop the core? All active connections will be dropped.')) return;
    try{ const r=await fetch('/api/service/stop',{method:'POST'}); if(!r.ok)throw 0; toast('Core stopped'); }catch(e){ toast('Error',true);} 
  } else {
    try{ const r=await fetch('/api/service/restart',{method:'POST'}); if(!r.ok)throw 0; toast('Core started'); }catch(e){ toast('Error',true);} 
  }
  await loadStats();
}
async function restartService(){
  if(!confirm('Restart the core?')) return;
  try{ const r=await fetch('/api/service/restart',{method:'POST'}); if(!r.ok)throw 0; toast('Core restarted'); }catch(e){ toast('Error',true);} 
  await loadStats();
}
async function openLogs(){
  try{
    const r=await fetch('/api/logs'); const d=await r.json();
    let out='STATUS: '+(d.running?'Running':'Stopped')+'\n';
    out+='Traffic: '+fmtBytes(d.totals.bytes)+'  |  Requests: '+d.totals.requests+'  |  Errors: '+d.totals.errors+'\n';
    out+='\n── Active connections ('+d.connections.length+') ──\n';
    if(!d.connections.length) out+='(none)\n';
    d.connections.forEach(c=>{ out+=c.ip+'  '+(c.uuid||'').slice(0,8)+'…  '+fmtBytes(c.bytes)+'  '+(c.connected_at||'').slice(11,19)+'\n'; });
    out+='\n── Recent errors ('+d.errors.length+') ──\n';
    if(!d.errors.length) out+='(none)\n';
    d.errors.slice().reverse().forEach(e=>{ out+=(e.time||'').slice(11,19)+'  '+e.error+'\n'; });
    document.getElementById('logs-box').textContent=out;
    document.getElementById('logs-modal').classList.add('show');
  }catch(e){ toast('Failed to load logs',true);} 
}
async function openConfig(){
  try{
    const r=await fetch('/api/config'); const d=await r.json();
    document.getElementById('config-box').textContent=JSON.stringify(d,null,2);
    document.getElementById('config-modal').classList.add('show');
  }catch(e){ toast('Failed to load config',true);} 
}
function downloadBackup(){
  const a=document.createElement('a'); a.href='/api/backup'; a.download=''; document.body.appendChild(a); a.click(); a.remove();
  toast('Backup downloaded');
}
function checkUpdate(){
  toast('NyxRelay '+(apiStats.panelVersion||'')+' — you are on the latest version');
}

// ── Inbounds ─────────────────────────────────────────────────
async function loadInbounds() {
  try {
    const r = await fetch('/api/links');
    if (!r.ok) throw new Error();
    const d = await r.json();
    allLinks = d.links || [];
    filterInbounds();
    if (document.getElementById('ib-total')) document.getElementById('ib-total').textContent = allLinks.length;
    if (document.getElementById('ib-clients')) document.getElementById('ib-clients').textContent = allLinks.filter(l=>l.active).length;
  } catch(e) {
    document.getElementById('inbounds-tbody').innerHTML = '<tr><td colspan="7" style="text-align:center;padding:32px;color:#555">Failed to load inbounds</td></tr>';
  }
}

function setFilter(f, el) {
  currentFilter = f;
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  filterInbounds();
}

function filterInbounds() {
  const q = (document.getElementById('inbound-search')?.value||'').toLowerCase();
  let filtered = allLinks;
  if (currentFilter === 'active') filtered = filtered.filter(l => l.active);
  if (currentFilter === 'disabled') filtered = filtered.filter(l => !l.active);
  if (q) filtered = filtered.filter(l => l.label.toLowerCase().includes(q) || l.uuid.toLowerCase().includes(q));
  renderInbounds(filtered);
}

function renderInbounds(links) {
  const tbody = document.getElementById('inbounds-tbody');
  if (!links.length) {
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state">No inbounds found</div></td></tr>';
    return;
  }
  let idx = links.length;
  tbody.innerHTML = links.map(l => {
    const u = l.used_bytes, lim = l.limit_bytes;
    const uF = fmtBytes(u), lF = fmtLimit(lim);
    const pct = lim > 0 ? Math.min(100, (u/lim)*100) : 0;
    const col = pct>90?'#ef4444':pct>70?'#fbbf24':'#008771';
    const i = idx--;
    const maxC = l.max_connections || 0;
    const curC = l.current_connections || 0;
    return `<tr>
      <td style="color:#555;font-size:11px">${i}</td>
      <td style="font-weight:600;color:#ccc">${esc(l.label)}</td>
      <td><span class="ant-tag ant-tag-purple">VLESS</span></td>
      <td>
        <div class="usage-pill">
          <span class="used">${uF}</span>
          <div class="bar"><div class="fill" style="width:${pct}%;background:${col}"></div></div>
          <span class="limit">${lF}</span>
        </div>
      </td>
      <td style="font-size:12px;font-weight:600;color:${maxC>0&&curC>=maxC?'#ef4444':'#888'}">${curC}/${maxC||'∞'}</td>
      <td><span class="ant-tag ${l.active?'ant-tag-green':'ant-tag-red'}">${l.active?'On':'Off'}</span></td>
      <td>
        <div style="display:flex;gap:3px;align-items:center">
          <button class="toggle ${l.active?'on':''}" data-uid="${l.uuid}" onclick="toggleInbound(this)" title="Toggle"></button>
          <button class="ant-btn ant-btn-secondary ant-btn-sm" onclick="showEditModal('${l.uuid}')" style="padding:3px 7px;color:#fbbf24;border-color:rgba(251,191,36,0.2);background:rgba(251,191,36,0.06)">e</button>
          <button class="btn-copy" onclick="copyVless('${esc(l.vless_link)}')" title="Copy VLESS">c</button>
          <button class="btn-copy" onclick="copySubUrl('${l.uuid}')" style="background:rgba(34,197,94,0.08);color:#22c55e;border-color:rgba(34,197,94,0.15)" title="Copy Sub URL">s</button>
          <button class="btn-qr" onclick="showQR('${esc(l.vless_link)}')" title="QR">QR</button>
          <button class="ant-btn ant-btn-danger ant-btn-sm" onclick="deleteInbound('${l.uuid}')" title="Delete">x</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

async function toggleInbound(el) {
  const uid = el.dataset.uid;
  const link = allLinks.find(l => l.uuid === uid);
  if (!link) return;
  try {
    await fetch(`/api/links/${uid}`, {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({active:!link.active})});
    await loadInbounds();
    await loadStats();
  } catch(e) { toast('Error', true); }
}

async function createInbound() {
  const label = document.getElementById('new-label').value.trim();
  if (!label) { toast('Name is required', true); return; }
  if (!/^[a-zA-Z0-9\-_. ]+$/.test(label)) { toast('Only English letters, numbers, - _ . space', true); return; }
  const val = parseFloat(document.getElementById('new-limit').value)||0;
  const unit = document.getElementById('new-unit').value;
  const maxconn = parseInt(document.getElementById('new-maxconn').value)||0;
  const expiry = parseInt(document.getElementById('new-expiry').value)||0;
  try {
    const r = await fetch('/api/links', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({label,limit_value:val,limit_unit:unit,max_connections:maxconn,expiry_days:expiry})});
    if (!r.ok) { const d=await r.json().catch(()=>({})); throw new Error(d.detail||'Error'); }
    toast('Inbound created');
    document.getElementById('new-label').value='';
    document.getElementById('new-limit').value='';
    document.getElementById('new-maxconn').value='';
    document.getElementById('new-expiry').value='';
    closeModal('add-modal');
    await loadInbounds();
    await loadStats();
  } catch(e) { toast(e.message, true); }
}

async function deleteInbound(uid) {
  if (!confirm('Delete this inbound?')) return;
  try {
    await fetch(`/api/links/${uid}`, {method:'DELETE'});
    toast('Deleted');
    await loadInbounds();
    await loadStats();
  } catch(e) { toast('Error', true); }
}

function showEditModal(uid) {
  const l = allLinks.find(x => x.uuid === uid);
  if (!l) return;
  document.getElementById('edit-uid').value = uid;
  document.getElementById('edit-name').value = l.label;
  const gb = l.limit_bytes / 1073741824;
  document.getElementById('edit-limit').value = l.limit_bytes > 0 ? gb.toFixed(2) : '';
  document.getElementById('edit-unit').value = 'GB';
  document.getElementById('edit-maxconn').value = l.max_connections > 0 ? l.max_connections : '';
  document.getElementById('edit-title').textContent = 'Edit: ' + l.label;
  document.getElementById('edit-modal').classList.add('show');
}

async function saveEdit() {
  const uid = document.getElementById('edit-uid').value;
  const val = parseFloat(document.getElementById('edit-limit').value)||0;
  const unit = document.getElementById('edit-unit').value;
  const maxconn = parseInt(document.getElementById('edit-maxconn').value)||0;
  try {
    const r = await fetch(`/api/links/${uid}`, {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({limit_value:val,limit_unit:unit,max_connections:maxconn})});
    if (!r.ok) throw new Error();
    toast('Updated');
    closeModal('edit-modal');
    await loadInbounds();
  } catch(e) { toast('Error', true); }
}

async function resetTraffic() {
  const uid = document.getElementById('edit-uid').value;
  if (!confirm('Reset traffic to zero?')) return;
  try {
    await fetch(`/api/links/${uid}`, {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({reset_usage:true})});
    toast('Traffic reset');
    await loadInbounds();
  } catch(e) { toast('Error', true); }
}

function copyVless(txt) { navigator.clipboard.writeText(txt).then(()=>toast('VLESS link copied')).catch(()=>toast('Copy failed',true)); }
async function copySubUrl(uid) {
  const url = `https://${location.host}/sub/${uid}`;
  navigator.clipboard.writeText(url).then(()=>toast('Subscription URL copied')).catch(()=>toast('Copy failed',true));
}
function showQR(txt) {
  if (!txt) return;
  document.getElementById('qr-img').src = 'https://api.qrserver.com/v1/create-qr-code/?size=280x280&data=' + encodeURIComponent(txt);
  document.getElementById('qr-modal').classList.add('show');
}
function downloadQR() {
  const img = document.getElementById('qr-img');
  if (!img.src) return;
  const a = document.createElement('a'); a.href=img.src; a.download='nyxrelay-qr.png'; a.click();
}

// ── Addresses ────────────────────────────────────────────────
let allAddresses = [];
async function loadAddresses() {
  try {
    const r = await fetch('/api/addresses');
    if (!r.ok) throw new Error();
    const d = await r.json();
    allAddresses = d.addresses || [];
    renderAddresses();
  } catch(e) {}
}
function renderAddresses() {
  const list = document.getElementById('address-list');
  if (!allAddresses.length) { list.innerHTML = '<div style="color:#555;font-size:12px;padding:8px 0">No addresses added</div>'; return; }
  list.innerHTML = allAddresses.map((a,i) => `
    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:#111;border:1px solid #1a1a1a;border-radius:8px;margin-bottom:6px">
      <span style="font-family:monospace;font-size:13px;color:#ccc">${esc(a)}</span>
      <button class="ant-btn ant-btn-danger ant-btn-sm" onclick="deleteAddress(${i})">×</button>
    </div>`).join('');
}
function showAddAddressModal() { document.getElementById('new-address').value=''; document.getElementById('add-address-modal').classList.add('show'); }
async function addAddresses() {
  const text = document.getElementById('new-address').value.trim();
  if (!text) { toast('Enter at least one address', true); return; }
  const lines = text.split('\n').map(l=>l.trim()).filter(l=>l);
  let added=0, errors=0;
  for (const addr of lines) {
    if (!/^[a-zA-Z0-9\-_. ]+$/.test(addr)) { errors++; continue; }
    try {
      const r = await fetch('/api/addresses', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({address:addr})});
      if (r.ok) added++; else errors++;
    } catch(e) { errors++; }
  }
  if (added > 0) toast(`Added ${added} address(es)`);
  if (errors > 0) toast(`${errors} failed`, true);
  if (added > 0) { closeModal('add-address-modal'); await loadAddresses(); }
}
async function deleteAddress(index) {
  if (!confirm('Delete this address?')) return;
  try {
    const r = await fetch(`/api/addresses/${index}`, {method:'DELETE'});
    if (!r.ok) throw new Error();
    toast('Deleted');
    await loadAddresses();
  } catch(e) { toast('Error', true); }
}

// ── Domain ───────────────────────────────────────────────────
let currentDomain = '';
async function loadDomain() {
  try {
    const r = await fetch('/api/domain');
    if (!r.ok) throw new Error();
    const d = await r.json();
    currentDomain = d.domain || '';
    const renderDomain = apiStats.domain || location.host;
    const rd = document.getElementById('render-domain');
    if (rd) rd.textContent = renderDomain;
    const dv = document.getElementById('domain-value');
    const dcb = document.getElementById('domain-clear-btn');
    if (currentDomain) {
      dv.textContent = currentDomain;
      dv.style.color = '#008771';
      if (dcb) dcb.style.display = '';
    } else {
      dv.textContent = renderDomain + ' (default)';
      dv.style.color = '#888';
      if (dcb) dcb.style.display = 'none';
    }
  } catch(e) {}
}
async function saveDomain() {
  const domain = document.getElementById('domain-input').value.trim();
  if (!domain) { toast('Enter a domain', true); return; }
  try {
    const r = await fetch('/api/domain', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({domain})});
    if (!r.ok) { const d=await r.json().catch(()=>({})); throw new Error(d.detail||'Error'); }
    toast('Domain saved');
    document.getElementById('domain-input').value = '';
    await loadDomain();
  } catch(e) { toast(e.message, true); }
}
async function clearDomain() {
  try {
    await fetch('/api/domain', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({domain:''})});
    toast('Domain cleared');
    await loadDomain();
  } catch(e) { toast('Error', true); }
}

// ── Settings ─────────────────────────────────────────────────
async function changePassword() {
  const cur = document.getElementById('cur-pw').value;
  const nw = document.getElementById('new-pw').value;
  const conf = document.getElementById('confirm-pw').value;
  if (!cur || !nw || !conf) { toast('Fill all fields', true); return; }
  if (nw !== conf) { toast('Passwords do not match', true); return; }
  if (nw.length < 4) { toast('Min 4 characters', true); return; }
  try {
    const r = await fetch('/api/change-password', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({current_password:cur,new_password:nw})});
    if (!r.ok) { const d=await r.json().catch(()=>({})); throw new Error(d.detail||'Error'); }
    toast('Password updated');
    document.getElementById('cur-pw').value='';
    document.getElementById('new-pw').value='';
    document.getElementById('confirm-pw').value='';
  } catch(e) { toast(e.message, true); }
}

async function doLogout() {
  await fetch('/api/logout', {method:'POST'});
  location.href = '/login';
}

// ── Init ─────────────────────────────────────────────────────
loadStats();
loadInbounds();
setInterval(loadStats, 5000);
setInterval(loadInbounds, 15000);
</script>
</body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

# Legacy route aliases
@app.get("/inbounds", response_class=HTMLResponse)
async def inbounds_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return RedirectResponse(url="/dashboard")

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return RedirectResponse(url="/dashboard")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
