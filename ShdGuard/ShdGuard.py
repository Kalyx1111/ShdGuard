#!/usr/bin/env python3
"""
ShdGuard - passive defensive intrusion alerts with attacker attribution.
By Aryan / @EPureNest

Passive only. Watches this PC's own sockets and processes and, on Windows, failed logons
(Event 4625). Looks up ONLY the attacker's public IP against public intelligence sources,
writes hash-sealed evidence plus a draft abuse report that YOU send yourself.
It never connects to, scans, probes or sends data to any attacker host.
"""
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import psutil
    import requests
except ImportError as exc:
    print(f"Missing dependency ({exc}). Run ShdRun.bat or ShdRun.sh once while online.")
    input("\nPress Enter to exit...")
    sys.exit(1)

HOME = Path(__file__).resolve().parent
DATA, EVID, FEEDS = HOME / "data", HOME / "evidence", HOME / "data" / "feeds"
for _folder in (DATA, EVID, FEEDS):
    _folder.mkdir(parents=True, exist_ok=True)
DB_PATH, HB_PATH, LOG_PATH = DATA / "shd.db", DATA / "heartbeat.json", DATA / "shd.log"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"  # keyless public feed
FEODO_MAX_AGE, CACHE_TTL, HTTP_TIMEOUT = 6 * 3600, 24 * 3600, 10
POLL_SECONDS, LOGON_EVERY, RETRY_EVERY = 20, 300, 600
VT_MIN_GAP = 15  # VirusTotal public API: 4 requests per minute
UA = "ShdGuard/1.0 (personal defensive monitor)"
TEMP_PATH = re.compile(r"[\\/](temp|tmp)[\\/]", re.IGNORECASE)
EV_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
ANY_ADDR = ("0.0.0.0", "::")
SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT, first_seen TEXT NOT NULL, kind TEXT NOT NULL,
    remote_ip TEXT, remote_port INTEGER, local_port INTEGER, proc TEXT, pid INTEGER, exe TEXT,
    exe_sha256 TEXT, detail TEXT, dedupe_key TEXT UNIQUE NOT NULL, record_sha256 TEXT NOT NULL,
    enrich_status TEXT NOT NULL DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS enrich_cache (ip TEXT PRIMARY KEY, ts REAL NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def cfg(name):
    """Secrets and settings come from environment variables only. Nothing is written to disk."""
    return os.environ.get(name, "").strip() or None


ABUSE_KEY, GN_KEY, VT_KEY = cfg("SHD_ABUSEIPDB_KEY"), cfg("SHD_GREYNOISE_KEY"), cfg("SHD_VT_KEY")
NTFY_TOPIC, NTFY_URL = cfg("SHD_NTFY_TOPIC"), cfg("SHD_NTFY_URL") or "https://ntfy.sh"
PHONE_OK = bool(NTFY_TOPIC and re.fullmatch(r"[A-Za-z0-9_-]{16,64}", NTFY_TOPIC)
                and NTFY_URL.startswith("https://"))


def now_utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def utc_day():
    return now_utc()[:10]


def log(msg, level="INFO"):
    line = f"{now_utc()} [{level}] {msg}"
    print(line, flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def public_ip(text):
    """Validated, globally routable address, else None. Private and loopback ranges get no lookups."""
    try:
        ip = ipaddress.ip_address(str(text or "").strip())
    except ValueError:
        return None
    return ip if ip.is_global else None


def sha256_file(path, limit=300 * 1024 * 1024):
    try:
        if os.path.getsize(path) > limit:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                digest.update(block)
        return digest.hexdigest()
    except (OSError, TypeError):
        return None


def proc_info(pid):
    if not pid:
        return "unknown", None
    try:
        proc = psutil.Process(pid)
        return proc.name(), proc.exe()
    except (psutil.Error, OSError):
        return "unknown", None


def open_db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.executescript(SCHEMA)
    return con


def kv_get(con, key, default=None):
    row = con.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    return row[0] if row else default


def kv_set(con, key, value):
    con.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", (key, str(value)))
    con.commit()


def write_heartbeat(state):
    HB_PATH.write_text(json.dumps({"state": state, "pid": os.getpid(), "ts": time.time(),
                                   "utc": now_utc()}), encoding="utf-8")


# ---------- incidents and evidence ----------

def record_incident(con, kind, dedupe_key, exe, **fields):
    rec = {"kind": kind, "first_seen": now_utc(), "exe": exe, **fields}
    digest = hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    cur = con.execute(
        "INSERT OR IGNORE INTO incidents (first_seen, kind, remote_ip, remote_port, local_port, proc, pid, "
        "exe, exe_sha256, detail, dedupe_key, record_sha256) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (rec["first_seen"], kind, rec.get("remote_ip"), rec.get("remote_port"), rec.get("local_port"),
         rec.get("proc"), rec.get("pid"), exe, rec.get("exe_sha256"), rec.get("detail"), dedupe_key, digest))
    con.commit()
    if not cur.rowcount:
        return None, None, None
    return cur.lastrowid, rec, digest


def write_evidence(inc_id, rec, digest, enrichment, intel):
    doc = {"incident_id": inc_id, "record": rec, "record_sha256": digest,
           "enrichment": enrichment, "file_intel": intel, "written_utc": now_utc()}
    path = EVID / f"incident_{inc_id:06d}.json"
    path.write_text(json.dumps(doc, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path


def write_report(inc_id, rec, enrichment):
    contacts = enrichment.get("sources", {}).get("ripe_abuse_contacts", {}).get("abuse_contacts") or ["none listed"]
    text = (
        f"Subject: Malicious network activity from {rec.get('remote_ip') or 'unknown source'} (ref SHD-{inc_id:06d})\n"
        f"Abuse contact(s) for the address (RIPE, may be outdated): {', '.join(contacts)}\n\n"
        f"Observed (UTC): {rec['first_seen']}\n"
        f"Activity: {rec['kind']}\n"
        f"Source: {rec.get('remote_ip') or '-'} port {rec.get('remote_port') or '-'}\n"
        f"Detail: {rec.get('detail')}\n\n"
        "Full hash-sealed incident record available on request.\n"
        "Redacted: victim host name, user account names and victim public IP.\n"
    )
    path = EVID / f"report_{inc_id:06d}.txt"
    path.write_text(text, encoding="utf-8")
    return path


def verify_evidence():
    total, bad = 0, []
    for path in sorted(EVID.glob("incident_*.json")):
        total += 1
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            digest = hashlib.sha256(json.dumps(doc["record"], sort_keys=True, default=str).encode("utf-8")).hexdigest()
            if digest != doc["record_sha256"]:
                bad.append(path.name)
        except (OSError, ValueError, KeyError):
            bad.append(path.name)
    return total, bad


def process_incident(con, kind, dedupe_key, exe=None, **fields):
    if con.execute("SELECT 1 FROM incidents WHERE dedupe_key=?", (dedupe_key,)).fetchone():
        return
    exe_sha = sha256_file(exe) if exe else None
    inc_id, rec, digest = record_incident(con, kind, dedupe_key, exe, exe_sha256=exe_sha, **fields)
    if inc_id is None:
        return
    ip = public_ip(rec.get("remote_ip"))
    enrichment = enrich_ip(con, ip) if ip is not None else {"complete": True, "note": "no public address, no lookups"}
    intel = safe_call(src_virustotal_hash, exe_sha) if (VT_KEY and exe_sha) else None
    write_evidence(inc_id, rec, digest, enrichment, intel)
    report = write_report(inc_id, rec, enrichment)
    con.execute("UPDATE incidents SET enrich_status=? WHERE id=?",
                ("done" if enrichment.get("complete") else "pending", inc_id))
    con.commit()
    summary = (f"#{inc_id} {kind} | from {rec.get('remote_ip') or '-'}:{rec.get('remote_port') or '-'} | "
               f"process {rec.get('proc')} | {rec.get('detail')}")
    log(f"{summary} | evidence/incident_{inc_id:06d}.json | {report.name}", "ALERT")
    notify_phone(f"ShdGuard: {kind}", summary)


# ---------- attribution sources (public, read-only, the attacker is never contacted) ----------

def get_json(url, params=None, headers=None):
    resp = requests.get(url, params=params, headers={"User-Agent": UA, **(headers or {})}, timeout=HTTP_TIMEOUT)
    try:
        body = resp.json()
    except ValueError:
        body = {}
    return resp.status_code, body


def safe_call(fn, arg):
    try:
        return fn(arg)
    except Exception as exc:  # offline, TLS, quota or parse problems are recorded, never fatal
        return {"error": type(exc).__name__}


def src_ripe(ip):
    status, body = get_json("https://stat.ripe.net/data/abuse-contact-finder/data.json", {"resource": ip})
    if status != 200:
        return {"error": f"HTTP {status}"}
    data = body.get("data", {})
    return {"abuse_contacts": data.get("abuse_contacts", []), "authoritative_rir": data.get("authoritative_rir")}


def src_abuseipdb(ip):
    status, body = get_json("https://api.abuseipdb.com/api/v2/check", {"ipAddress": ip, "maxAgeInDays": 90},
                            {"Key": ABUSE_KEY, "Accept": "application/json"})
    if status != 200:
        return {"error": f"HTTP {status}"}
    data = body.get("data", {})
    return {k: data.get(k) for k in ("abuseConfidenceScore", "totalReports", "lastReportedAt",
                                     "isp", "usageType", "countryCode")}


def src_greynoise(ip):
    status, body = get_json(f"https://api.greynoise.io/v3/community/{ip}", headers={"key": GN_KEY})
    if status == 404:
        return {"result": "not observed by GreyNoise"}
    if status != 200:
        return {"error": f"HTTP {status}"}
    return {k: body.get(k) for k in ("noise", "riot", "classification", "name", "last_seen")}


_vt_last = [0.0]


def src_virustotal_hash(sha):
    if not (VT_KEY and re.fullmatch(r"[0-9a-f]{64}", sha or "")):
        return {"error": "not configured or invalid hash"}
    wait = VT_MIN_GAP - (time.time() - _vt_last[0])
    if wait > 0:
        time.sleep(wait)
    _vt_last[0] = time.time()
    status, body = get_json(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey": VT_KEY})
    if status == 404:
        return {"result": "hash unknown to VirusTotal"}
    if status != 200:
        return {"error": f"HTTP {status}"}
    attr = body.get("data", {}).get("attributes", {})
    return {"name": attr.get("meaningful_name"), "last_analysis_stats": attr.get("last_analysis_stats")}


def enrich_ip(con, ip_obj):
    ip = str(ip_obj)
    row = con.execute("SELECT ts, data FROM enrich_cache WHERE ip=?", (ip,)).fetchone()
    if row and time.time() - row[0] < CACHE_TTL:
        return json.loads(row[1])
    result = {"ip": ip, "reverse_dns": None, "sources": {}}
    try:
        result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
    except OSError:
        pass
    result["sources"]["ripe_abuse_contacts"] = safe_call(src_ripe, ip)
    if ABUSE_KEY:
        result["sources"]["abuseipdb"] = safe_call(src_abuseipdb, ip)
    if GN_KEY:
        result["sources"]["greynoise"] = safe_call(src_greynoise, ip)
    result["complete"] = any("error" not in v for v in result["sources"].values())
    if result["complete"]:
        con.execute("INSERT OR REPLACE INTO enrich_cache (ip, ts, data) VALUES (?,?,?)",
                    (ip, time.time(), json.dumps(result)))
        con.commit()
    return result


def notify_phone(title, body):
    if not PHONE_OK:
        return
    try:
        requests.post(f"{NTFY_URL.rstrip('/')}/{NTFY_TOPIC}", data=body[:900].encode("utf-8"),
                      headers={"Title": title.encode("ascii", "ignore").decode(), "Priority": "high",
                               "User-Agent": UA}, timeout=HTTP_TIMEOUT)
    except Exception as exc:
        log(f"Phone push failed ({type(exc).__name__}); evidence is saved locally.", "WARN")


def load_c2_set():
    path = FEEDS / "feodo_ipblocklist.csv"
    if not path.exists() or time.time() - path.stat().st_mtime > FEODO_MAX_AGE:
        try:
            resp = requests.get(FEODO_URL, headers={"User-Agent": UA}, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(resp.content)
            tmp.replace(path)
            log("Feodo C2 blocklist refreshed.")
        except Exception as exc:
            log(f"Feodo refresh skipped ({type(exc).__name__}); using cached copy if present.", "WARN")
    ips = set()
    if path.exists():
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    row = next(csv.reader([line.lstrip("#").strip()]), [])
                    if len(row) >= 2:
                        ips.add(str(ipaddress.ip_address(row[1].strip())))
                except (ValueError, csv.Error):
                    continue
    return ips


# ---------- detection ----------

def scan_sockets(con, c2, baseline):
    conns = psutil.net_connections(kind="inet")
    exposed = {c.laddr.port for c in conns if c.status == "LISTEN" and c.laddr and c.laddr.ip in ANY_ADDR}
    for c in conns:
        if c.status == "LISTEN" and c.laddr and c.laddr.ip in ANY_ADDR:
            if c.laddr.port not in baseline:
                name, exe = proc_info(c.pid)
                process_incident(con, "NEW_EXPOSED_PORT", f"listen|{c.laddr.port}|{c.pid}", exe=exe,
                                 remote_ip=None, remote_port=None, local_port=c.laddr.port, pid=c.pid,
                                 proc=name, detail=f"new listener on all interfaces, port {c.laddr.port}")
            continue
        if c.status != "ESTABLISHED" or not c.raddr or not c.raddr.ip:
            continue
        ip = public_ip(c.raddr.ip)
        if ip is None:
            continue
        name, exe = proc_info(c.pid)
        local = c.laddr.port if c.laddr else None
        if str(ip) in c2:
            kind, why = "C2_MATCH", "remote IP is on the abuse.ch Feodo botnet C2 blocklist"
        elif local in exposed:
            kind, why = "INBOUND_TO_EXPOSED_PORT", f"outside connection into listening port {local}"
        elif exe and TEMP_PATH.search(exe):
            kind, why = "TEMP_PROCESS_NETWORK", "program running from a Temp folder has an outside connection"
        else:
            continue
        process_incident(con, kind, f"{kind}|{ip}|{local}|{c.pid}|{utc_day()}", exe=exe,
                         remote_ip=str(ip), remote_port=c.raddr.port, local_port=local,
                         pid=c.pid, proc=name, detail=why)


def parse_4625(xml_text):
    """Yield (EventRecordID, EventData dict) for each event in `wevtutil qe ... /f:xml` output."""
    body = re.sub(r"<\?xml[^>]*\?>", "", xml_text or "")
    root = ET.fromstring(f"<Events>{body}</Events>")
    for ev in root.iter(f"{EV_NS}Event"):
        rid = int(ev.findtext(f"{EV_NS}System/{EV_NS}EventRecordID") or 0)
        data = {d.get("Name", ""): (d.text or "") for d in ev.iter(f"{EV_NS}Data")}
        yield rid, data


def scan_failed_logons(con):
    if os.name != "nt":
        return
    try:
        out = subprocess.run(["wevtutil", "qe", "Security", "/q:*[System[(EventID=4625)]]", "/f:xml",
                              "/c:50", "/rd:true"], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"Failed-logon check unavailable ({type(exc).__name__}).", "WARN")
        return
    if out.returncode != 0:
        log("Failed-logon monitoring needs Administrator rights. Re-run ShdRun.bat as Administrator.", "WARN")
        return
    for rid, data in parse_4625(out.stdout):
        try:
            addr = ipaddress.ip_address(data.get("IpAddress", ""))
        except ValueError:
            continue
        if rid <= 0 or addr.is_loopback:
            continue
        port = data.get("IpPort", "")
        process_incident(con, "FAILED_LOGON", f"logon|{rid}", remote_ip=str(addr),
                         remote_port=int(port) if port.isdigit() else None, local_port=None, pid=None,
                         proc="Windows logon service",
                         detail=f"failed logon attempt, logon type {data.get('LogonType', '?')}",
                         target_account=data.get("TargetUserName", ""))


def retry_pending(con):
    rows = con.execute("SELECT id, remote_ip FROM incidents WHERE enrich_status='pending' "
                       "ORDER BY id DESC LIMIT 5").fetchall()
    for inc_id, remote in rows:
        ip = public_ip(remote)
        enrichment = enrich_ip(con, ip) if ip is not None else {"complete": True}
        if not enrichment.get("complete"):
            continue
        path = EVID / f"incident_{inc_id:06d}.json"
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            doc["enrichment"] = enrichment
            path.write_text(json.dumps(doc, indent=2, sort_keys=True, default=str), encoding="utf-8")
        except (OSError, ValueError) as exc:
            log(f"Could not update evidence for #{inc_id} ({type(exc).__name__}).", "WARN")
            continue
        con.execute("UPDATE incidents SET enrich_status='done' WHERE id=?", (inc_id,))
        con.commit()
        log(f"Enrichment completed for incident #{inc_id}.")


def learn_baseline(con):
    ports = sorted({c.laddr.port for c in psutil.net_connections(kind="inet")
                    if c.status == "LISTEN" and c.laddr and c.laddr.ip in ANY_ADDR})
    kv_set(con, "baseline_ports", ",".join(str(p) for p in ports))
    kv_set(con, "baseline_done", "1")
    log(f"Learning mode complete: {len(ports)} exposed listening port(s) stored as baseline.")


# ---------- resilience ----------

def check_previous_run():
    if not HB_PATH.exists():
        return
    try:
        hb = json.loads(HB_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        hb = {"state": "corrupt"}
    stale = hb.get("state") == "running" and time.time() - float(hb.get("ts", 0)) > 3 * POLL_SECONDS
    if not (stale or hb.get("state") == "corrupt"):
        return
    print(f"\nPrevious session did not stop cleanly (last heartbeat: {hb.get('utc', 'unknown')}).")
    choice = input("[R] Recover from last saved state   [D] Run diagnostic repair > ").strip().lower()
    if choice.startswith("d"):
        run_diagnostics()
    else:
        log("Recovering from last saved state (baselines and alert history are in data/shd.db).")


def online():
    try:
        socket.create_connection(("stat.ripe.net", 443), timeout=5).close()
        return True
    except OSError:
        return False


def run_diagnostics():
    con = None
    try:
        con = open_db()
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
    except sqlite3.DatabaseError as exc:
        integrity = f"unreadable ({type(exc).__name__})"
    if integrity != "ok":
        if con is not None:
            con.close()
        if DB_PATH.exists():
            backup = DB_PATH.with_name(f"shd_corrupt_{int(time.time())}.db")
            DB_PATH.replace(backup)
            log(f"Database failed integrity check; moved to {backup.name}. A fresh baseline will be learned.", "WARN")
        con = open_db()
    total, bad = verify_evidence()
    feed = FEEDS / "feodo_ipblocklist.csv"
    log(f"Diagnostics: database={integrity}; evidence files={total}, hash failures={len(bad)} {bad[:5]}; "
        f"C2 feed cached={feed.exists()}; tcp_reachable={'yes' if online() else 'no'}; keys set: "
        f"AbuseIPDB={bool(ABUSE_KEY)} GreyNoise={bool(GN_KEY)} VirusTotal={bool(VT_KEY)} phone={PHONE_OK}")
    con.close()


def main():
    check_previous_run()
    con = open_db()
    try:
        if "--diagnose" in sys.argv:
            con.close()
            run_diagnostics()
            return
        if "--selftest" in sys.argv:
            process_incident(con, "SELFTEST", f"selftest|{time.time()}", exe=None, remote_ip="203.0.113.10",
                             remote_port=4444, local_port=None, pid=None, proc="ShdGuard selftest",
                             detail="synthetic incident, documentation-only IP, no lookups performed")
            log("Selftest complete: see the evidence folder and, if configured, your phone.")
            return
        if kv_get(con, "baseline_done") is None:
            learn_baseline(con)
        log(f"ShdGuard running (passive only). Keys set: AbuseIPDB={bool(ABUSE_KEY)} GreyNoise={bool(GN_KEY)} "
            f"VirusTotal={bool(VT_KEY)} phone={PHONE_OK}. Press Ctrl+C to stop.")
        if NTFY_TOPIC and not PHONE_OK:
            log("SHD_NTFY_TOPIC or SHD_NTFY_URL is invalid; phone alerts disabled.", "WARN")
        c2, last_feed = load_c2_set(), time.time()
        last_logon = last_retry = 0.0
        while True:
            write_heartbeat("running")
            try:
                if time.time() - last_feed > FEODO_MAX_AGE:
                    c2, last_feed = load_c2_set(), time.time()
                baseline = {int(p) for p in kv_get(con, "baseline_ports", "").split(",") if p}
                scan_sockets(con, c2, baseline)
                if time.time() - last_logon > LOGON_EVERY:
                    scan_failed_logons(con)
                    last_logon = time.time()
                if time.time() - last_retry > RETRY_EVERY:
                    retry_pending(con)
                    last_retry = time.time()
            except Exception:  # self-healing: log the failure and keep watching
                log("Cycle error, monitoring continues:\n" + traceback.format_exc(), "ERROR")
            time.sleep(POLL_SECONDS)
    finally:
        con.close()


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except KeyboardInterrupt:
        log("Stopped by user.")
    except Exception:
        exit_code = 1
        log("Fatal error:\n" + traceback.format_exc(), "ERROR")
    finally:
        try:
            write_heartbeat("stopped")
        except OSError:
            pass
    input("\nPress Enter to exit...")
    sys.exit(exit_code)
