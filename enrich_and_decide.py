#!/usr/bin/env python3
# enrich_and_decide.py
# - Dedupe de IPs
# - Limite diário de consultas (default 1000 via MAX_DAILY_CHECKS)
# - Cache (evita checar IP consultado nas últimas 24h)
# - Auditoria em SQLite

import os, requests, time, sqlite3, datetime

BASE_DIR = "/opt/auto-block"
SRC = os.path.join(BASE_DIR, "logs", "suspects_raw.txt")
PENDING = os.path.join(BASE_DIR, "logs", "pending_blocklist.txt")
DB = os.path.join(BASE_DIR, "db", "auto_block.db")

ABUSE_KEY = os.getenv("ABUSEIPDB_KEY", "")
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
MIN_SCORE = int(os.getenv("MIN_SCORE", "30"))              # threshold
MAX_DAILY_CHECKS = int(os.getenv("MAX_DAILY_CHECKS", "1000"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", str(24*3600)))  # 24h

HEADERS = {'Key': ABUSE_KEY, 'Accept': 'application/json'}

def now_ts():
    return int(time.time())

def today_str_utc():
    # YYYY-MM-DD em UTC
    return datetime.datetime.utcnow().strftime("%Y-%m-%d")

def init_db():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    # auditoria de bloqueios
    cur.execute("""
      CREATE TABLE IF NOT EXISTS blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        score INTEGER,
        reports INTEGER,
        ts INTEGER,
        src_line TEXT
      );
    """)
    # cache de consultas AbuseIPDB
    cur.execute("""
      CREATE TABLE IF NOT EXISTS ip_cache (
        ip TEXT PRIMARY KEY,
        last_checked_ts INTEGER,
        last_score INTEGER,
        last_reports INTEGER
      );
    """)
    # controle de cota diária
    cur.execute("""
      CREATE TABLE IF NOT EXISTS api_usage (
        day TEXT PRIMARY KEY,
        count INTEGER
      );
    """)
    con.commit()
    con.close()

def get_daily_remaining():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("SELECT count FROM api_usage WHERE day = ?", (today_str_utc(),))
    row = cur.fetchone()
    used = row[0] if row else 0
    remaining = max(0, MAX_DAILY_CHECKS - used)
    con.close()
    return remaining, used

def inc_daily_used(n):
    if n <= 0:
        return
    con = sqlite3.connect(DB)
    cur = con.cursor()
    day = today_str_utc()
    cur.execute("INSERT INTO api_usage(day,count) VALUES(?,?) ON CONFLICT(day) DO UPDATE SET count=count+?", (day, n, n))
    con.commit()
    con.close()

def load_candidates():
    """
    Entrada do extract_suspects.sh:
    TIMESTAMP|IP|FULL_LINE
    Queremos IPs únicos, na ordem que chegaram (já prioriza os mais recentes do script).
    """
    if not os.path.exists(SRC):
        print("Arquivo de origem não existe:", SRC)
        return [], {}
    ips = []
    srcmap = {}  # ip -> (ts_str, full_line)
    with open(SRC) as f:
        for line in f:
            line = line.strip()
            if not line or '|' not in line:
                continue
            parts = line.split("|", 2)
            if len(parts) < 3:
                continue
            ts_str, ip, full = parts[0], parts[1], parts[2]
            if ip not in srcmap:
                srcmap[ip] = (ts_str, full)
                ips.append(ip)
    return ips, srcmap

def cache_is_fresh(ip):
    """
    Retorna True se já consultamos esse IP e o cache ainda é válido (últimas 24h por padrão)
    """
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("SELECT last_checked_ts FROM ip_cache WHERE ip = ?", (ip,))
    row = cur.fetchone()
    con.close()
    if not row:
        return False
    last_ts = row[0] or 0
    return (now_ts() - last_ts) < CACHE_TTL_SECONDS

def update_cache(ip, score, reports):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("""
      INSERT INTO ip_cache(ip,last_checked_ts,last_score,last_reports)
      VALUES(?,?,?,?)
      ON CONFLICT(ip) DO UPDATE SET last_checked_ts=excluded.last_checked_ts,
                                   last_score=excluded.last_score,
                                   last_reports=excluded.last_reports
    """, (ip, now_ts(), int(score), int(reports)))
    con.commit()
    con.close()

def abuse_check(ip):
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    try:
        r = requests.get(ABUSE_URL, headers=HEADERS, params=params, timeout=10)
        if r.status_code != 200:
            print(f"AbuseIPDB falhou {r.status_code} para {ip}: {r.text[:200]}")
            return None
        data = r.json().get('data', {})
        score = int(data.get('abuseConfidenceScore', 0))
        reports = int(data.get('totalReports', 0))
        return score, reports
    except Exception as e:
        print("Erro AbuseIPDB:", e)
        return None

def append_pending(ip, score, reports, ts_label):
    os.makedirs(os.path.dirname(PENDING), exist_ok=True)
    with open(PENDING, "a") as out:
        out.write(f"{ip} #score={score} #reports={reports} #t={now_ts()} #src={ts_label}\n")

def audit_block(ip, score, reports, full_line):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("INSERT INTO blocks (ip,score,reports,ts,src_line) VALUES (?,?,?,?,?)",
                (ip, int(score), int(reports), now_ts(), full_line))
    con.commit()
    con.close()

def main():
    if not ABUSE_KEY:
        print("ABUSEIPDB_KEY não definido. Exporte a variável e rode novamente.")
        return

    init_db()
    ips, srcmap = load_candidates()
    if not ips:
        print("Sem candidatos.")
        return

    remaining, used = get_daily_remaining()
    if remaining <= 0:
        print(f"Limite diário esgotado: {used}/{MAX_DAILY_CHECKS}.")
        return

    # 1) remover duplicados já feito em load_candidates; 2) filtrar por cache fresco
    to_query = []
    for ip in ips:
        if cache_is_fresh(ip):
            # já consultado nas últimas 24h — se quiser usar o score do cache,
            # poderíamos olhar ip_cache.last_score aqui; para simplificar, só pula.
            continue
        to_query.append(ip)

    if not to_query:
        print("Nada para consultar (todos em cache recente).")
        return

    # 3) respeitar o teto diário
    to_query = to_query[:remaining]
    print(f"Consultando {len(to_query)} IP(s). Restante da cota após execução será no máx. {remaining - len(to_query)}.")

    checked = 0
    for ip in to_query:
        res = abuse_check(ip)
        checked += 1
        if res is None:
            continue
        score, reports = res
        update_cache(ip, score, reports)

        # decisão simples por score
        if score >= MIN_SCORE:
            ts_label, full_line = srcmap.get(ip, ("", ""))
            append_pending(ip, score, reports, ts_label)
            audit_block(ip, score, reports, full_line)

        # (opcional) pequeno intervalo para ser "gentil" com a API gratuita
        time.sleep(0.1)

    inc_daily_used(checked)
    print(f"Feito. Consultados {checked} IP(s).")

if __name__ == "__main__":
    main()
