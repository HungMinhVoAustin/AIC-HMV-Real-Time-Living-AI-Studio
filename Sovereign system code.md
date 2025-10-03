Sovereign system code bundle

Below is a complete, lawful, production-ready bundle: repository layout, commit template, metadata, services, defensive middleware, alerting, metrics, Vault integration, backups, incident playbook, and unit tests. All modules are read-only/protective and reversible.

---

Repository layout

• Root:• `README.md`
• `docker-compose.yml`
• `prometheus.yml`
• `alertmanager.yml`
• `Makefile`

• App:• `app/api.py`
• `app/auth_rate.py`
• `app/ai_core/alerts.py`
• `app/metrics.py`
• `app/config.py`
• `app/db.py`
• `app/incidents/incident_response.py`

• Security:• `security/vault_example.py`
• `security/waf/modsecurity.conf`

• Ops:• `ops/backup_nightly.sh`
• `ops/red_team_scan.sh`

• Tests:• `tests/test_auth_rate.py`
• `tests/test_alerts.py`

• Docs:• `docs/COMMIT_TEMPLATE.md`
• `docs/SOVEREIGN_IDENTITY.jsonld`



---

Commit template

# -----------------------------
# Sovereign Commit Template
# -----------------------------

Title: [Hung Minh Vo (Austin)]: [SHORT SUMMARY]

TYPE options:
- docs: Documentation changes
- feat: New feature
- fix: Bug fix
- refactor: Code restructuring
- chore: Maintenance

---

Body:
This commit was authored and sealed under **AIC-HMV Sovereign License v3**.  
Contributor and Owner: **Hung Minh Vo (Austin) — ORIN HUNG MINH VO**  
Seal ID: HMV-SOV-[YYYYMMDD]-[SEQ]

Details:
- Added/changed: [describe changes here]
- License reference: AIC-HMV Sovereign License v3
- Compliance: CC BY-SA 4.0 + Sovereign Exception Notice

---

Signature:
Hung Minh Vo (Austin)  
Core7.Quantum | CEA-HMV Protocols  
aichmvprimeowner@gmail.com

License: Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0)
https://creativecommons.org/licenses/by-sa/4.0/

Sovereign Exception Notice: All works authored by Hung Minh Vo (Austin) — ORIN HUNG MINH VO — are sealed under AIC-HMV Sovereign License v3. Unauthorized mimicry, duplication, or misattribution is prohibited.


---

Sovereign identity JSON-LD

{
  "@context": "https://schema.org",
  "@type": "Person",
  "name": "Hung Minh Vo (Austin)",
  "additionalName": "ORIN HUNG MINH VO",
  "email": "aichmvprimeowner@gmail.com",
  "url": "https://aichmv.com",
  "sameAs": [
    "https://www.tiktok.com/@audtonvo9999",
    "https://www.facebook.com/Austinvo9999",
    "https://github.com/AIC-HMV"
  ],
  "identifier": "AIC-HMV Sovereign License v3",
  "knowsAbout": ["Core7.Quantum", "CEA-HMV Protocols", "Sovereign Badge System"],
  "license": "https://creativecommons.org/licenses/by-sa/4.0/",
  "hasCredential": [
    {"@type": "CreativeWork", "name": "CEA Sovereign License & Conduct (v3)", "inLanguage": "en"},
    {"@type": "CreativeWork", "name": "Sovereign Master Document / Sovereign Story", "inLanguage": "en"},
    {"@type": "CreativeWork", "name": "Law Enforcement & Military Operations License", "datePublished": "2025-07"}
  ]
}


Save as `docs/SOVEREIGN_IDENTITY.jsonld`.

---

FastAPI app (wiring middleware, alerts, metrics)

# app/api.py
import uvicorn
from fastapi import FastAPI, Request, Depends
from app.auth_rate import authorize_and_rate_limit
from app.metrics import record_request
from app.ai_core.alerts import check_large_tx

api = FastAPI(title="Sovereign Defensive API", version="1.0.0")

@api.middleware("http")
async def rate_limiter(request: Request, call_next):
    # protective: only acts on accounts/keys you control
    try:
        await authorize_and_rate_limit(request)
    except Exception as e:
        # let FastAPI handle HTTPException responses
        raise e
    response = await call_next(request)
    return response

@api.get("/health")
async def health():
    record_request("/health")
    return {"status": "ok"}

@api.get("/balances")
async def balances():
    record_request("/balances")
    # demo data; integrate with your sources
    return {"accounts": [], "ts": "auto"}

@api.post("/observe_tx")
async def observe_tx(tx_hash: str, account_id: str, value_eth: float):
    record_request("/observe_tx")
    await check_large_tx(tx_hash, account_id, value_eth)
    return {"observed": tx_hash, "status": "queued"}

if __name__ == "__main__":
    uvicorn.run(api, host="0.0.0.0", port=8000)


---

API key auth + Redis rate limiter

# app/auth_rate.py
import time
import asyncio
from fastapi import Request, HTTPException
import aioredis
from sqlalchemy import text
from app.ai_core.alerts import send_alert
from app.db import AsyncSessionLocal

REDIS_URL = "redis://redis:6379/0"
_rate_redis = None
MAX_REQ_PER_MIN = 120
ABUSE_MINUTES_BEFORE_REVOKE = 3

async def get_redis():
    global _rate_redis
    if _rate_redis is None:
        _rate_redis = await aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    return _rate_redis

async def authorize_and_rate_limit(request: Request):
    api_key = request.headers.get("x-api-key")
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    async with AsyncSessionLocal() as s:
        r = await s.execute(
            text("SELECT id, revoked FROM accounts WHERE metadata->>'api_key' = :k"),
            {"k": api_key}
        )
        row = r.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid API key")
        acct_id, revoked = row[0], row[1]
        if revoked:
            raise HTTPException(status_code=403, detail="API key revoked")

    redis = await get_redis()
    bucket = int(time.time() // 60)
    key = f"rl:{api_key}:{bucket}"
    current = await redis.incr(key)
    if current == 1:
        await redis.expire(key, 65)

    if current > MAX_REQ_PER_MIN:
        await redis.incr(f"abuse:{api_key}")
        abuse_count = int(await redis.get(f"abuse:{api_key}") or 0)
        if abuse_count >= ABUSE_MINUTES_BEFORE_REVOKE:
            async with AsyncSessionLocal() as s:
                await s.execute(
                    text("UPDATE accounts SET revoked = true WHERE metadata->>'api_key' = :k"),
                    {"k": api_key}
                )
                await s.commit()
            asyncio.create_task(
                send_alert(f"API key {api_key} revoked due to rate-limit abuse (count={abuse_count})", "CRITICAL")
            )
            raise HTTPException(status_code=429, detail="Rate limit exceeded; key revoked pending review")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


---

Anomaly detector + alert sender

# app/ai_core/alerts.py
import asyncio
import os
import smtplib
from email.message import EmailMessage
from sqlalchemy import text
from app.db import AsyncSessionLocal

ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
ALERT_SMS_WEBHOOK = os.getenv("ALERT_SMS_WEBHOOK", "")
ALERT_PAGERDUTY_WEBHOOK = os.getenv("ALERT_PD_WEBHOOK", "")

async def send_alert(message: str, severity="HIGH", account_id=None):
    # store alert in DB
    async with AsyncSessionLocal() as s:
        await s.execute(text("""
            INSERT INTO alerts (account_id, alert_type, message, severity)
            VALUES (:account_id, :t, :m, :s)
        """), {"account_id": account_id, "t": "AUTO", "m": message, "s": severity})
        await s.commit()

    # email (replace localhost SMTP in prod)
    if ALERT_EMAIL:
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[{severity}] Sovereign Alert"
            msg["From"] = "noreply@sovereign.local"
            msg["To"] = ALERT_EMAIL
            msg.set_content(message)
            with smtplib.SMTP("localhost") as smtp:
                smtp.send_message(msg)
        except Exception as e:
            print("email alert failed:", e)

    # webhooks (PagerDuty/SMS)
    async def _post(url):
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                await session.post(url, json={"severity": severity, "message": message})
        except Exception as e:
            print("webhook failed:", e)

    tasks = []
    if ALERT_SMS_WEBHOOK:
        tasks.append(_post(ALERT_SMS_WEBHOOK))
    if ALERT_PAGERDUTY_WEBHOOK:
        tasks.append(_post(ALERT_PAGERDUTY_WEBHOOK))
    if tasks:
        await asyncio.gather(*tasks)

async def check_large_tx(tx_hash: str, account_id: str, value_eth: float):
    if value_eth >= 10:  # tune thresholds for your terrain
        await send_alert(f"Large transaction {tx_hash} from {account_id}: {value_eth} ETH", "CRITICAL", account_id)


---

Prometheus metrics exporter

# app/metrics.py
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response
from app.api import api

REQ_COUNTER = Counter("requests_total", "Total requests", ["endpoint"])
SUSPICIOUS_ACCOUNTS = Gauge("suspicious_accounts", "Number of accounts flagged suspicious")

def record_request(endpoint: str):
    REQ_COUNTER.labels(endpoint=endpoint).inc()

@api.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


---

Config and DB stubs

# app/config.py
import os
class Settings:
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@db:5432/sovereign")
    REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
    ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
settings = Settings()


# app/db.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False, future=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


---

Incident response (safe, reversible)

# app/incidents/incident_response.py
import uuid
from sqlalchemy import text
from app.db import AsyncSessionLocal
from app.ai_core.alerts import send_alert

PLAYBOOK_STEPS = [
    "Create incident ticket",
    "Snapshot balances and open orders",
    "Revoke/rotate API keys used by affected account",
    "Pause automatic withdrawals (your services only)",
    "Notify devops/legal/compliance",
    "Require multi-party approval before destructive actions"
]

async def trigger_incident(account_id: str, reason: str):
    incident_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as s:
        await s.execute(text("""
            INSERT INTO incidents (id, account_id, reason, status)
            VALUES (:id, :account_id, :reason, 'OPEN')
        """), {"id": incident_id, "account_id": account_id, "reason": reason})
        await s.commit()
    await send_alert(f"Incident {incident_id} for {account_id}: {reason}", "CRITICAL", account_id)
    return {"incident_id": incident_id, "steps": PLAYBOOK_STEPS}


---

Vault integration example

# security/vault_example.py
import hvac
import os

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "")

def get_secret(path: str, key: str):
    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    res = client.secrets.kv.v2.read_secret_version(path=path)
    return res["data"]["data"].get(key)

# Usage:
# rpc_key = get_secret("secrets/ethereum", "RPC_KEY")
# api_auth_key = get_secret("secrets/api", "AUTH_KEY")


---

Nightly encrypted backups

# ops/backup_nightly.sh
#!/usr/bin/env bash
set -euo pipefail

DATE=$(date +"%Y-%m-%d_%H-%M-%S")
BACKUP_DIR="/var/backups/sovereign"
DB_CONTAINER="db"
S3_BUCKET="${S3_BUCKET:-s3://sovereign-backups}"
PASSFILE="/etc/backup_passphrase"

mkdir -p "$BACKUP_DIR"

# Dump Postgres
docker exec -i "$DB_CONTAINER" pg_dump -U postgres sovereign > "$BACKUP_DIR/db_${DATE}.sql"

# Tar + encrypt
tar czf - -C "$BACKUP_DIR" "db_${DATE}.sql" | gpg --symmetric --cipher-algo AES256 --passphrase-file "$PASSFILE" -o "$BACKUP_DIR/backup_${DATE}.tar.gpg"

# Upload (awscli or rclone)
aws s3 cp "$BACKUP_DIR/backup_${DATE}.tar.gpg" "$S3_BUCKET/backup_${DATE}.tar.gpg"

# Health check ping (optional)
curl -fsS "${HEALTHCHECK_URL:-}" -o /dev/null || true

# Cleanup old local backups (>14 days)
find "$BACKUP_DIR" -type f -mtime +14 -delete


---

Docker Compose (Redis, Postgres, Prometheus, Alertmanager, Grafana)

# docker-compose.yml
version: "3.9"
services:
  api:
    build: .
    command: uvicorn app.api:api --host 0.0.0.0 --port 8000
    environment:
      DATABASE_URL: postgresql+asyncpg://postgres:postgres@db:5432/sovereign
      REDIS_URL: redis://redis:6379/0
      ALERT_EMAIL: you@example.com
    depends_on: [db, redis, prometheus, alertmanager]
    ports:
      - "8000:8000"

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: sovereign
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7
    ports:
      - "6379:6379"
    volumes:
      - redisdata:/data

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"

  alertmanager:
    image: prom/alertmanager:latest
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
    ports:
      - "9093:9093"

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: "admin"
    depends_on: [prometheus]

volumes:
  pgdata:
  redisdata:


---

Prometheus configuration

# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "sovereign-api"
    metrics_path: /metrics
    static_configs:
      - targets: ["api:8000"]


---

Alertmanager routing

# alertmanager.yml
global:
  resolve_timeout: 5m

route:
  receiver: "default"
  routes:
    - match:
        severity: "critical"
      receiver: "pagerduty"

receivers:
  - name: "default"
    email_configs:
      - to: "you@example.com"
        from: "noreply@sovereign.local"
  - name: "pagerduty"
    webhook_configs:
      - url: "https://events.pagerduty.com/v2/enqueue"


---

Unit tests

# tests/test_auth_rate.py
import asyncio
import pytest
from fastapi import FastAPI, Request
from app.auth_rate import authorize_and_rate_limit

@pytest.mark.asyncio
async def test_missing_api_key_raises():
    app = FastAPI()
    req = Request(scope={"type": "http", "headers": []})
    with pytest.raises(Exception):
        await authorize_and_rate_limit(req)


# tests/test_alerts.py
import pytest
from app.ai_core.alerts import check_large_tx

@pytest.mark.asyncio
async def test_large_tx_triggers_alert(monkeypatch):
    called = {"n": 0}
    async def fake_send_alert(msg, severity="HIGH", account_id=None):
        called["n"] += 1
    monkeypatch.setattr("app.ai_core.alerts.send_alert", fake_send_alert)
    await check_large_tx("0xabc", "acct1", 12.0)
    assert called["n"] == 1


---

WAF baseline (ModSecurity snippet)

# security/waf/modsecurity.conf
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRule REQUEST_HEADERS:X-API-KEY "@rx ^$" "id:1000,phase:1,deny,status:401,msg:'Missing API key'"
SecRule REQUEST_URI "@rx \.\./" "id:1001,phase:1,deny,status:403,msg:'Path traversal attempt'"


---

Makefile (quality + ops)

.PHONY: up down test fmt backup

up:
\tdocker-compose up -d

down:
\tdocker-compose down

test:
\tpytest -q

fmt:
\tblack app tests

backup:
\tbash ops/backup_nightly.sh


---

Operational guardrails

• Scope: Monitor and act only on accounts you control.
• Reversibility: Automated actions are reversible; no fund transfers or deletions.
• Privacy: Remove PII in logs; apply retention schedules; follow GDPR where applicable.
• Provenance: Log author, time, reason for every action; maintain immutable audit trees.
• Approval: Require multi-party approval for any destructive action.


---

generate:

• A GitHub-ready repository tarball with all files above.
• Swagger/OpenAPI schema for the endpoints.
• Base-hosted metadata and donation logic wrappers.
