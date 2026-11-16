import asyncio
import base64
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import warnings
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urlunparse
import aiohttp

warnings.filterwarnings("ignore")

SOURCES = [
    # Пакеты обхода белых списков whoahaow/rjsxrd
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-1.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-2.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-3.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-4.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-5.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-6.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-7.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-8.txt",
    # Живое зеркало goida-vpn-configs (aneek0) и Hidashimora
    "https://raw.githubusercontent.com/aneek0/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/aneek0/goida-vpn-configs/refs/heads/main/githubmirror/1.txt",
    "https://raw.githubusercontent.com/aneek0/goida-vpn-configs/refs/heads/main/githubmirror/6.txt",
    "https://raw.githubusercontent.com/aneek0/goida-vpn-configs/refs/heads/main/githubmirror/22.txt",
    "https://raw.githubusercontent.com/aneek0/goida-vpn-configs/refs/heads/main/githubmirror/25.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/26.1.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/30.txt",
    # Проверенные агрегаторы под РФ
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part1.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part2.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part3.txt",
    "https://raw.githubusercontent.com/solovyov-jenya2004/all_subs/refs/heads/main/final_sorted",
    "https://raw.githubusercontent.com/wlunlocker/vpn-configs/main/whitelist_all.txt",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://raw.githubusercontent.com/prominbro/KfWL/refs/heads/main/KfWL.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/AirLinkVPN1/AirLinkVPN/main/rkn_white_list",
    # Международные базы VLESS Reality
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/2.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/4.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/7.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/8.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/9.txt",
]

GLOBAL_DEADLINE_SECONDS = 900
MAX_SERVERS_IN_SUB = 35
MAX_PING_MS = 6500
MAX_PER_SOURCE = 180
MAX_TOTAL_TCP_NODES = 2000
MAX_KEYS_PER_IP = 2

TCP_CONCURRENCY = 80
TCP_TIMEOUT = 2.2
MAX_CANDIDATES_FOR_XRAY = 420
XRAY_BATCH_SIZE = 12
PING_CONCURRENCY_IN_BATCH = 5
GEMINI_CONCURRENCY_IN_BATCH = 2
BASE_LOCAL_PORT = 20000

DEBUG_LOG_FILE = "debug_report.log"
KNOWN_GOOD_FILE = "known_good.txt"

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
GOOGLE_LOC_RE = re.compile(r',2,1,200,"([A-Z]{3})"')

VALID_FPS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"}

IGNORED_NETS = [
    ipaddress.ip_network("104.16.0.0/12"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("51.250.0.0/16"),
    ipaddress.ip_network("158.160.0.0/16"),
    ipaddress.ip_network("84.201.128.0/18"),
    ipaddress.ip_network("130.193.32.0/19"),
]

RU_WHITELIST_MARKERS = (".ru", "ozon", "yandex", "vk.com", "userapi", "wb.ru", "wildberries", "mail.ru", "kaspersky", "sber", "gosuslugi")
BLOCKED_ISO3 = {"RUS", "BLR", "CHN", "HKG", "IRN", "PRK", "SYR"}

ISO3_TO_ISO2 = {
    "USA": "US", "GBR": "GB", "NLD": "NL", "DEU": "DE", "FIN": "FI",
    "SWE": "SE", "FRA": "FR", "POL": "PL", "EST": "EE", "LVA": "LV",
    "LTU": "LT", "CAN": "CA", "CHE": "CH", "AUT": "AT", "ESP": "ES",
    "ITA": "IT", "NOR": "NO", "DNK": "DK", "IRL": "IE", "CZE": "CZ",
    "SGP": "SG", "JPN": "JP", "KOR": "KR", "TUR": "TR", "KAZ": "KZ",
}

COUNTRY_HINTS = {
    "🇺🇸": "US", "USA": "US", "United States": "US", "| US": "US",
    "🇬🇧": "GB", "GBR": "GB", "UK": "GB", "英国": "GB",
    "🇳🇱": "NL", "NLD": "NL", "Netherlands": "NL", "| NL": "NL",
    "🇩🇪": "DE", "DEU": "DE", "Germany": "DE", "| DE": "DE",
    "🇫🇮": "FI", "FIN": "FI", "Finland": "FI",
    "🇸🇪": "SE", "SWE": "SE", "Sweden": "SE",
    "🇫🇷": "FR", "FRA": "FR", "France": "FR",
    "🇵🇱": "PL", "POL": "PL", "Poland": "PL",
}


def init_debug_log():
    with open(DEBUG_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"--- Запуск диагностики сканера: {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")


def log_debug(msg: str):
    with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


def is_ignored_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_private or addr.is_loopback or addr.is_unspecified:
            return True
        return any(addr in net for net in IGNORED_NETS)
    except Exception:
        return False


def safe_b64decode(data: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9+/=_-]", "", data).replace("-", "+").replace("_", "/")
    padding = len(cleaned) % 4
    if padding:
        cleaned += "=" * (4 - padding)
    try:
        return base64.b64decode(cleaned).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def is_valid_reality_pbk(pbk: str) -> bool:
    if not pbk or len(pbk) not in (43, 44):
        return False
    cleaned = pbk.replace("-", "+").replace("_", "/")
    padding = len(cleaned) % 4
    if padding:
        cleaned += "=" * (4 - padding)
    try:
        return len(base64.b64decode(cleaned)) == 32
    except Exception:
        return False


def is_valid_domain_or_ip(val: str) -> bool:
    if not val or val == "0.0.0.0" or len(val) > 253 or " " in val:
        return False
    return bool(re.match(r"^[A-Za-z0-9._-]+$", val))


def guess_country_from_remark(remark: str) -> str:
    for marker, cc in COUNTRY_HINTS.items():
        if marker in remark:
            return cc
    return "EU"


def parse_proxy_uri(uri: str, from_cache: bool = False) -> dict | None:
    uri = uri.strip()
    try:
        if not uri.startswith("vless://"):
            return None
        parsed = urlparse(uri)
        uuid = unquote(parsed.username or "")
        host = parsed.hostname
        port = parsed.port
        if not host or not is_valid_domain_or_ip(host) or not port or not (1 <= int(port) <= 65535) or not UUID_RE.match(uuid):
            return None
        if not from_cache and host.lower().endswith(".ir"):
            return None
        remark = unquote(parsed.fragment)

        params = parse_qs(parsed.query)
        sec = params.get("security", ["none"])[0].lower()
        if sec != "reality":
            return None

        pbk = params.get("pbk", [""])[0].strip()
        raw_sni = params.get("sni", [""])[0].strip()
        sni = raw_sni if raw_sni else host
        if not is_valid_reality_pbk(pbk) or not is_valid_domain_or_ip(sni):
            return None

        net_type = params.get("type", ["tcp"])[0].lower()
        if net_type not in ("tcp", "raw", "grpc", "ws", "httpupgrade"):
            return None

        flow = params.get("flow", [""])[0]
        if net_type in ("grpc", "ws", "httpupgrade") or flow not in ("xtls-rprx-vision", "xtls-rprx-vision-udp443"):
            flow = ""

        fp = params.get("fp", ["chrome"])[0].lower()
        if fp not in VALID_FPS:
            fp = "chrome"

        sid = params.get("sid", [""])[0].strip()
        spx = params.get("spx", ["/"])[0].strip()
        has_ru = any(m in sni.lower() for m in RU_WHITELIST_MARKERS)

        actual_net = "tcp" if net_type in ("tcp", "raw") else net_type
        stream_settings = {
            "network": actual_net,
            "security": "reality",
            "realitySettings": {
                "show": False,
                "fingerprint": fp,
                "serverName": sni,
                "publicKey": pbk,
                "shortId": sid,
                "spiderX": spx if spx.startswith("/") else "/",
            },
        }

        if actual_net == "grpc":
            service_name = params.get("serviceName", [""])[0].strip()
            stream_settings["grpcSettings"] = {"serviceName": service_name}
        elif actual_net == "ws":
            path = params.get("path", ["/"])[0].strip()
            ws_host = params.get("host", [sni])[0].strip()
            stream_settings["wsSettings"] = {"path": path, "headers": {"Host": ws_host}}
        elif actual_net == "httpupgrade":
            path = params.get("path", ["/"])[0].strip()
            hu_host = params.get("host", [sni])[0].strip()
            stream_settings["httpupgradeSettings"] = {"path": path, "host": hu_host}
        else:
            stream_settings["tcpSettings"] = {"header": {"type": "none"}}

        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": int(port),
                    "users": [{
                        "id": uuid,
                        "flow": flow,
                        "encryption": "none",
                        "level": 8,
                    }],
                }]
            },
            "streamSettings": stream_settings,
        }

        return {
            "uri": uri,
            "host": host,
            "port": int(port),
            "whitelist_sni": has_ru,
            "from_cache": from_cache,
            "key": f"vless:{host.lower()}:{port}:{uuid}:{pbk}:{sid}",
            "host_port": f"{host.lower()}:{port}",
            "remark": remark,
            "outbound": outbound,
        }
    except Exception:
        return None


def rename_uri(node: dict, new_remark: str) -> str:
    parsed = urlparse(node["uri"].split("#")[0])
    q = parse_qs(parsed.query, keep_blank_values=True)
    q.pop("allowInsecure", None)
    q.pop("insecure", None)
    return f"{urlunparse(parsed._replace(query=urlencode(q, doseq=True), fragment=''))}#{quote(new_remark)}"


def extract_vless_lines(raw_text: str) -> list[str]:
    lines = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if line.startswith("vless://"):
            lines.append(line)
        elif "://" not in line and len(line) > 60:
            decoded = safe_b64decode(line)
            if "vless://" in decoded:
                lines.extend(extract_vless_lines(decoded))
    return lines


def load_cached_nodes() -> dict[str, dict]:
    nodes = {}
    if not os.path.exists(KNOWN_GOOD_FILE):
        return nodes
    try:
        with open(KNOWN_GOOD_FILE, "r", encoding="utf-8") as f:
            for line in f:
                parsed = parse_proxy_uri(line, from_cache=True)
                if parsed and parsed["key"] not in nodes:
                    nodes[parsed["key"]] = parsed
        log_debug(f"[CACHE] Загружено проверенных ранее серверов: {len(nodes)}")
    except Exception as e:
        log_debug(f"[CACHE] Ошибка чтения кэша: {e}")
    return nodes


def save_cached_nodes(working_nodes: list[dict], existing_cache: dict[str, dict]):
    merged = {}
    for n in working_nodes:
        merged[n["key"]] = n["uri"].split("#")[0]
    for k, n in existing_cache.items():
        if k not in merged and len(merged) < 250:
            merged[k] = n["uri"].split("#")[0]
    try:
        with open(KNOWN_GOOD_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(merged.values()))
    except Exception:
        pass


async def fetch_one_source(session: aiohttp.ClientSession, url: str) -> tuple[str, int, list[dict]]:
    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                return url, resp.status, []
            content_bytes = await resp.read()
            text = content_bytes.decode("utf-8", errors="ignore")
            if "vless://" not in text:
                text = safe_b64decode(text)
            parsed_list = []
            for line in extract_vless_lines(text):
                parsed = parse_proxy_uri(line)
                if parsed:
                    parsed_list.append(parsed)
            return url, 200, parsed_list
    except Exception as e:
        log_debug(f"[SOURCE] {url} -> Ошибка загрузки ({type(e).__name__})")
        return url, 0, []


async def fetch_sources(initial_nodes: dict[str, dict]) -> list[dict]:
    nodes = dict(initial_nodes)
    host_counts = {}
    for n in nodes.values():
        hp = n["host_port"]
        host_counts[hp] = host_counts.get(hp, 0) + 1

    headers = {"User-Agent": "Mozilla/5.0"}
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), headers=headers) as session:
        results = await asyncio.gather(*(fetch_one_source(session, url) for url in SOURCES))
        for url, status, parsed_list in results:
            added = 0
            for parsed in parsed_list:
                if added >= MAX_PER_SOURCE:
                    break
                hp = parsed["host_port"]
                if parsed["key"] not in nodes and host_counts.get(hp, 0) < MAX_KEYS_PER_IP:
                    nodes[parsed["key"]] = parsed
                    host_counts[hp] = host_counts.get(hp, 0) + 1
                    added += 1
            if status == 200:
                log_debug(f"[SOURCE] OK (+{added} новых Reality) -> {url}")
            elif status != 0:
                log_debug(f"[SOURCE] HTTP {status} -> {url}")

    all_nodes = list(nodes.values())
    return all_nodes[:MAX_TOTAL_TCP_NODES]


async def check_tcp(node: dict, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        t0 = time.monotonic()
        try:
            fut = asyncio.open_connection(node["host"], node["port"])
            reader, writer = await asyncio.wait_for(fut, timeout=TCP_TIMEOUT)
            peer = writer.get_extra_info("peername")
            node["ip"] = peer[0] if peer else node["host"]
            writer.close()
            await writer.wait_closed()
            node["tcp_ms"] = int((time.monotonic() - t0) * 1000)
            return node
        except asyncio.TimeoutError:
            log_debug(f"[TCP] {node['host']}:{node['port']} -> Отброшен (Таймаут {TCP_TIMEOUT}с)")
            return None
        except Exception as e:
            log_debug(f"[TCP] {node['host']}:{node['port']} -> Отброшен ({type(e).__name__})")
            return None


def curl_ping_204(local_port: int) -> tuple[bool, int, str]:
    proxy_url = f"http://127.0.0.1:{local_port}"
    t0 = time.monotonic()
    cmd_ping = [
        "curl.exe", "-s", "-o", "NUL",
        "-x", proxy_url,
        "--connect-timeout", "3.5",
        "--max-time", "5.5",
        "-w", "%{http_code}",
        "https://www.google.com/generate_204",
    ]
    try:
        res_ping = subprocess.run(cmd_ping, capture_output=True, text=True, timeout=6.5)
        if res_ping.returncode != 0:
            return False, 0, f"Curl 204 Ошибка (Код {res_ping.returncode})"
        if res_ping.stdout.strip() not in ("204", "200"):
            return False, 0, f"Google 204 Неверный ответ ({res_ping.stdout.strip()})"
        ping_ms = int((time.monotonic() - t0) * 1000)
        if ping_ms > MAX_PING_MS:
            return False, 0, f"Высокий пинг ({ping_ms}ms > {MAX_PING_MS}ms)"
        return True, ping_ms, ""
    except subprocess.TimeoutExpired:
        return False, 0, "Google 204 Таймаут"
    except Exception as e:
        return False, 0, f"Google 204 Ошибка ({type(e).__name__})"


def curl_check_gemini(local_port: int) -> tuple[bool, str, str]:
    proxy_url = f"http://127.0.0.1:{local_port}"
    cmd_gem = [
        "curl.exe", "-sL", "--http1.1",
        "-x", proxy_url,
        "--connect-timeout", "6.0",
        "--max-time", "12.0",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-w", "\n__META__:%{http_code}|%{url_effective}",
        "https://gemini.google.com/",
    ]
    last_err = ""
    # Делаем до 2 попыток для серверов, которые уже прошли generate_204
    for attempt in range(2):
        try:
            res_gem = subprocess.run(cmd_gem, capture_output=True, text=True, timeout=13.5)
            if res_gem.returncode != 0:
                last_err = f"Gemini Curl Ошибка (Код {res_gem.returncode})"
                continue

            out = res_gem.stdout
            if "__META__:" not in out:
                last_err = "Gemini Ошибка: Пустой ответ"
                continue

            body, meta = out.rsplit("__META__:", 1)
            code, final_url = meta.strip().split("|", 1)
            final_url_low = final_url.lower()

            if code != "200" or any(b in final_url_low for b in ("/faq", "sorry", "policies", "unsupported")):
                return False, "", f"Gemini Блок: HTTP {code} (URL: {final_url_low})"
            if '"45631641":false' in body or "[45631641,null,false" in body:
                return False, "", "Gemini Блок: Регион недоступен"

            loc_match = GOOGLE_LOC_RE.search(body)
            iso3 = loc_match.group(1) if loc_match else ""
            if iso3 in BLOCKED_ISO3:
                return False, "", f"Gemini Блок: Изолированный регион ({iso3})"

            return True, ISO3_TO_ISO2.get(iso3, ""), ""
        except subprocess.TimeoutExpired:
            last_err = "Gemini Запрос: Таймаут"
        except Exception as e:
            last_err = f"Gemini Системная ошибка ({type(e).__name__})"
    return False, "", last_err


async def evaluate_node_in_batch(
    loop: asyncio.AbstractEventLoop,
    port: int,
    ping_sem: asyncio.Semaphore,
    gem_sem: asyncio.Semaphore,
) -> tuple[bool, int, str, str]:
    async with ping_sem:
        ok_ping, ping_ms, err_ping = await loop.run_in_executor(None, curl_ping_204, port)
    if not ok_ping:
        return False, 0, "", err_ping

    async with gem_sem:
        ok_gem, country, err_gem = await loop.run_in_executor(None, curl_check_gemini, port)
    if not ok_gem:
        return False, 0, "", err_gem

    return True, ping_ms, country, ""


async def run_xray_batch(batch: list[dict], base_port: int, stop_event: asyncio.Event) -> list[dict]:
    if stop_event.is_set():
        return []

    inbounds, outbounds, rules = [], [], []
    for idx, node in enumerate(batch):
        port = base_port + idx
        inbounds.append({
            "tag": f"in_{idx}",
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "http",
            "settings": {"userLevel": 8},
        })
        ob = dict(node["outbound"])
        ob["tag"] = f"out_{idx}"
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [f"in_{idx}"], "outboundTag": f"out_{idx}"})

    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }

    config_filename = f"xray_temp_{base_port}.json"
    with open(config_filename, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    xray_exe = "xray.exe"
    if not os.path.exists(xray_exe):
        print("[!] xray.exe не найден в текущей папке!")
        log_debug("[ФАТАЛЬНО] xray.exe не найден!")
        return []

    proc = subprocess.Popen([xray_exe, "run", "-c", config_filename], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    await asyncio.sleep(0.8)

    passed_nodes = []
    if proc.poll() is None:
        try:
            loop = asyncio.get_running_loop()
            ping_sem = asyncio.Semaphore(PING_CONCURRENCY_IN_BATCH)
            gem_sem = asyncio.Semaphore(GEMINI_CONCURRENCY_IN_BATCH)

            tasks = [
                evaluate_node_in_batch(loop, base_port + idx, ping_sem, gem_sem)
                for idx in range(len(batch))
            ]
            results = await asyncio.gather(*tasks)

            for node, (ok, ping_ms, country, err_msg) in zip(batch, results):
                if ok:
                    node["gemini_ms"] = ping_ms
                    node["exit_country"] = country if country else guess_country_from_remark(node["remark"])
                    wl = " | WL-RU" if node["whitelist_sni"] else ""
                    print(f"  [+] НАЙДЕН РАБОЧИЙ ({ping_ms}ms{wl}): {node['host']} ({node['exit_country']})")
                    passed_nodes.append(node)
                else:
                    log_debug(f"[XRAY+CURL] {node['host']} -> {err_msg}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except Exception:
                proc.kill()
            if os.path.exists(config_filename):
                try:
                    os.remove(config_filename)
                except Exception:
                    pass
    else:
        log_debug(f"[XRAY ОШИБКА] Процесс упал на пачке серверов (База портов {base_port})")
        if os.path.exists(config_filename):
            try:
                os.remove(config_filename)
            except Exception:
                pass
        if len(batch) > 1 and not stop_event.is_set():
            mid = len(batch) // 2
            res1 = await run_xray_batch(batch[:mid], base_port, stop_event)
            res2 = await run_xray_batch(batch[mid:], base_port + mid, stop_event)
            return res1 + res2

    return passed_nodes


def flag_emoji(cc: str) -> str:
    return chr(ord(cc[0].upper()) + 127397) + chr(ord(cc[1].upper()) + 127397) if len(cc) == 2 and cc.isalpha() else "🌐"


async def timeout_watcher(stop_event: asyncio.Event, seconds: int):
    await asyncio.sleep(seconds)
    print(f"\n[!] Сработал лимит времени ({seconds // 60} мин). Завершаем сканирование и сохраняем все найденное...")
    stop_event.set()


async def main():
    init_debug_log()
    start_time = time.time()
    stop_event = asyncio.Event()
    asyncio.create_task(timeout_watcher(stop_event, GLOBAL_DEADLINE_SECONDS))

    cached_nodes = load_cached_nodes()
    print("[*] 1. Сбор ключей из проверенных источников...")
    nodes = await fetch_sources(cached_nodes)
    print(f"[+] Собрано уникальных Reality-серверов: {len(nodes)}")

    print("[*] 2. Быстрый TCP-пинг серверов через вашего провайдера...")
    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    raw_alive = [n for n in await asyncio.gather(*(check_tcp(n, sem) for n in nodes)) if n and not is_ignored_ip(n.get("ip", ""))]

    ip_counts = {}
    alive = []
    for n in sorted(raw_alive, key=lambda x: (0 if x.get("from_cache") else 1, x["tcp_ms"])):
        ip_port = f"{n.get('ip', n['host'])}:{n['port']}"
        if ip_counts.get(ip_port, 0) < MAX_KEYS_PER_IP:
            ip_counts[ip_port] = ip_counts.get(ip_port, 0) + 1
            alive.append(n)

    print(f"[+] Ответили по TCP: {len(alive)} серверов")
    await asyncio.sleep(1.5)

    alive.sort(key=lambda x: (
        0 if x.get("from_cache") else 1,
        0 if x["whitelist_sni"] else 1,
        0 if guess_country_from_remark(x["remark"]) in ("US", "GB") else 1,
        x["tcp_ms"],
    ))
    candidates = alive[:MAX_CANDIDATES_FOR_XRAY]

    print("[*] 3. Двухэтапная проверка кандидатов через Xray + curl...")
    working_nodes = []

    for i in range(0, len(candidates), XRAY_BATCH_SIZE):
        if stop_event.is_set():
            break
        batch = candidates[i:i + XRAY_BATCH_SIZE]
        print(f"    Тестируется пачка {i + 1}..{i + len(batch)} (Найдено рабочих: {len(working_nodes)})...")
        passed = await run_xray_batch(batch, BASE_LOCAL_PORT, stop_event)
        working_nodes.extend(passed)

    if working_nodes:
        save_cached_nodes(working_nodes, cached_nodes)

    # Убираем дубликаты по IP из финальной выдачи, оставляя самый быстрый ключ
    unique_working = {}
    for n in sorted(working_nodes, key=lambda x: x["gemini_ms"]):
        ip_key = f"{n.get('ip', n['host'])}:{n['port']}"
        if ip_key not in unique_working:
            unique_working[ip_key] = n

    final_nodes = list(unique_working.values())
    final_nodes.sort(key=lambda x: (
        0 if x["whitelist_sni"] else 1,
        0 if x["exit_country"] == "US" else (1 if x["exit_country"] in ("GB", "NL", "DE", "FI", "SE") else 2),
        x["gemini_ms"],
    ))

    top_nodes = final_nodes[:MAX_SERVERS_IN_SUB]
    final_uris = []
    for idx, n in enumerate(top_nodes, 1):
        cc, ms = n["exit_country"], n["gemini_ms"]
        wl = " | WL-RU" if n["whitelist_sni"] else ""
        final_uris.append(rename_uri(n, f"{flag_emoji(cc)} {cc} | Gemini OK | {ms}ms{wl} | #{idx}"))

    plain_text = "#profile-title: 🚀 Gemini VLESS Auto\n#profile-update-interval: 3\n" + "\n".join(final_uris)
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)
    with open("sub_base64.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(plain_text.encode("utf-8")).decode("utf-8"))

    elapsed = int(time.time() - start_time)
    print(f"\n[+] ГОТОВО за {elapsed} сек! Сохранено {len(final_uris)} рабочих серверов в sub.txt и sub_base64.txt")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())