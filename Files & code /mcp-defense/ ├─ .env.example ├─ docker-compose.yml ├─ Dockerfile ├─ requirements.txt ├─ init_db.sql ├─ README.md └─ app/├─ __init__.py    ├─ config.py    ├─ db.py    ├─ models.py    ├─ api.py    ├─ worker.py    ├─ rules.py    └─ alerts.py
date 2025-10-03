Files & code

Create this folder structure:
mcp-defense/
├─ .env.example
├─ docker-compose.yml
├─ Dockerfile
├─ requirements.txt
├─ init_db.sql
├─ README.md
└─ app/
   ├─ __init__.py
   ├─ config.py
   ├─ db.py
   ├─ models.py
   ├─ api.py
   ├─ worker.py
   ├─ rules.py
   └─ alerts.py

.env.example
# copy to .env and edit
DATABASE_URL=postgresql+asyncpg://postgres:example@db:5432/monitor
API_HOST=0.0.0.0
API_PORT=8000

# alerting
ALERT_WEBHOOK_URL=    # e.g. https://hooks.example.com/endpoint
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
ALERT_FROM=no-reply@example.com
ALERT_TO=security@example.com

# operational
POLL_INTERVAL_SECONDS=5
RETENTION_DAYS=90
API_KEY=replace-with-api-key

docker-compose.yml
version: "3.8"
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: example
      POSTGRES_DB: monitor
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  api:
    build: .
    command: uvicorn app.api:app --host 0.0.0.0 --port 8000 --reload
    ports:
      - "8000:8000"
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - ./:/usr/src/app
    env_file:
      - .env

  worker:
    build: .
    command: python -u app/worker.py
    depends_on:
      db:
        condition: service_healthy
    env_file:
      - .env
    volumes:
      - ./:/usr/src/app

volumes:
  pgdata:


Dockerfile

FROM python:3.11-slim

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y build-essential libpq-dev curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel
RUN pip install -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

requirements.txt
fastapi==0.95.2
uvicorn[standard]==0.22.0
sqlalchemy==2.0.22
asyncpg==0.27.0
pydantic==2.5.1
python-dotenv==1.0.0
aiohttp==3.8.5
alembic==1.11.1
aiosmtplib==1.1.8
httpx==0.24.1


init_db.sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source TEXT,
  event_type TEXT,
  payload JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID REFERENCES events(id),
  rule_name TEXT,
  severity TEXT,
  message TEXT,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT now(),
  acknowledged BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);

app/__init__.py
# make package

app/config.py
from pydantic import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    ALERT_WEBHOOK_URL: str | None = None
    SMTP_HOST: str | None = None
    SMTP_PORT: int = 587
    SMTP_USER: str | None = None
    SMTP_PASS: str | None = None
    ALERT_FROM: str | None = None
    ALERT_TO: str | None = None
    POLL_INTERVAL_SECONDS: int = 5
    RETENTION_DAYS: int = 90
    API_KEY: str

    class Config:
        env_file = ".env"

settings = Settings()

app/db.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.config import settings

engine = create_async_engine(settings.DATABASE_URL, future=True, echo=False)
AsyncSessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


app/models.py
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String, JSON, TIMESTAMP, text
from sqlalchemy.dialects.postgresql import UUID
import datetime

Base = declarative_base()

class Event(Base):
    __tablename__ = "events"
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    source = Column(String)
    event_type = Column(String)
    payload = Column(JSON)
    created_at = Column(TIMESTAMP(timezone=True), default=datetime.datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    event_id = Column(UUID(as_uuid=True))
    rule_name = Column(String)
    severity = Column(String)
    message = Column(String)
    metadata = Column(JSON)
    created_at = Column(TIMESTAMP(timezone=True), default=datetime.datetime.utcnow)
    acknowledged = Column(String, default=False)


app/rules.py — simple, extensible rule engine


"""
Simple rule checks. Rules return None or dict(alert_info)
Extend this module with lawful detection logic only.
"""
from typing import Dict, Any
import time

def rule_brute_force(event: Dict[str, Any]) -> Dict | None:
    """
    Example: detect many failed login attempts from same account/IP within short window.
    This rule is illustrative — production must aggregate across events in DB.
    """
    if event.get("event_type") != "auth":
        return None
    payload = event.get("payload", {})
    action = payload.get("action")
    if action == "login_failed":
        # Minimal example: include details for correlation by worker
        return {
            "rule_name": "brute_force_suspected",
            "severity": "medium",
            "message": "Login failures detected — requires correlation",
            "metadata": {"account": payload.get("account"), "ip": payload.get("ip")}
        }
    return None

def rule_unusual_location(event: Dict[str, Any]) -> Dict | None:
    """
    Example: flag 'login_success' when geolocation differs drastically.
    DO NOT attempt to deanonymize people. Use for operator review only.
    """
    if event.get("event_type") != "auth":
        return None
    payload = event.get("payload", {})
    if payload.get("action") == "login_success":
        # placeholder: real geo checks require historical user data and consent
        if payload.get("geo", {}).get("country") and payload.get("geo", {}).get("country") != payload.get("account_country"):
            return {
                "rule_name": "geo_mismatch",
                "severity": "low",
                "message": "Login from a different country than account default",
                "metadata": {"account": payload.get("account")}
            }
    return None

# add new rule functions here and include them in RULES below
RULES = [rule_brute_force, rule_unusual_location]



app/alerts.py
import httpx
import json
import aiosmtplib
from app.config import settings
from typing import Dict, Any

async def send_webhook_alert(payload: Dict[str, Any]):
    if not settings.ALERT_WEBHOOK_URL:
        return
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            await client.post(settings.ALERT_WEBHOOK_URL, json=payload, timeout=10.0)
        except Exception as e:
            # log to stderr/file in production; avoid stdout if using stdio transport
            print("webhook error", e)

async def send_email_alert(subject: str, body: str):
    if not settings.SMTP_HOST or not settings.ALERT_TO or not settings.ALERT_FROM:
        return
    message = f"From: {settings.ALERT_FROM}\r\nTo: {settings.ALERT_TO}\r\nSubject: {subject}\r\n\r\n{body}"
    try:
        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASS,
            start_tls=True
        )
    except Exception as e:
        print("smtp error", e)

async def raise_alert(alert_info: Dict[str, Any], event: Dict[str, Any]):
    payload = {
        "alert": alert_info,
        "event": event
    }
    # non-blocking best-effort notifications
    await send_webhook_alert(payload)
    subject = f"[Alert] {alert_info.get('rule_name')} - {alert_info.get('severity')}"
    body = json.dumps(payload, default=str, indent=2)
    await send_email_alert(subject, body)


app/worker.py — processes events and applies rules
import asyncio
import json
import os
import time
from app.db import AsyncSessionLocal
from sqlalchemy import text
from app.rules import RULES
from app.alerts import raise_alert
from app.config import settings

async def fetch_unprocessed(session):
    # In this starter, just fetch recent events; in production build a proper queue or state flag.
    q = text("SELECT id, source, event_type, payload, created_at FROM events ORDER BY created_at DESC LIMIT 50")
    res = await session.execute(q)
    return [dict(row) for row in res.fetchall()]

async def insert_alert(session, event_id, alert_info):
    await session.execute(text("""
        INSERT INTO alerts (event_id, rule_name, severity, message, metadata)
        VALUES (:event_id, :rule_name, :severity, :message, :metadata)
    """), {
        "event_id": event_id,
        "rule_name": alert_info.get("rule_name"),
        "severity": alert_info.get("severity"),
        "message": alert_info.get("message"),
        "metadata": json.dumps(alert_info.get("metadata", {}))
    })
    await session.commit()

async def process_event(session, event):
    # event is dict mapping columns
    # run all rules
    for rule in RULES:
        try:
            alert = rule(event)
        except Exception as e:
            alert = None
        if alert:
            await insert_alert(session, event["id"], alert)
            # notify external systems
            await raise_alert(alert, event)

async def main_loop():
    while True:
        async with AsyncSessionLocal() as session:
            events = await fetch_unprocessed(session)
            # process each event
            for e in events:
                await process_event(session, e)
        await asyncio.sleep(settings.POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        pass

app/api.py — FastAPI endpoints
from fastapi import FastAPI, Depends, Header, HTTPException, status
from pydantic import BaseModel
from typing import Any, Optional
from app.db import AsyncSessionLocal
from app.config import settings
from sqlalchemy import text
import json
import asyncio

app = FastAPI(title="Defensive Monitor API")

# simple API key auth for demo
async def authorize(x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != settings.API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

class IngestEvent(BaseModel):
    source: str
    event_type: str
    payload: dict

@app.post("/ingest", dependencies=[Depends(authorize)])
async def ingest(event: IngestEvent):
    async with AsyncSessionLocal() as session:
        await session.execute(text("""
            INSERT INTO events (source, event_type, payload)
            VALUES (:source, :event_type, :payload)
        """), {"source": event.source, "event_type": event.event_type, "payload": json.dumps(event.payload)})
        await session.commit()
    return {"status": "ok"}

@app.get("/alerts", dependencies=[Depends(authorize)])
async def list_alerts(limit: int = 50):
    async with AsyncSessionLocal() as session:
        res = await session.execute(text("SELECT id, event_id, rule_name, severity, message, metadata, created_at, acknowledged FROM alerts ORDER BY created_at DESC LIMIT :l"), {"l": limit})
        rows = res.fetchall()
        return [dict(r) for r in rows]

@app.get("/events", dependencies=[Depends(authorize)])
async def list_events(limit: int = 100):
    async with AsyncSessionLocal() as session:
        res = await session.execute(text("SELECT id, source, event_type, payload, created_at FROM events ORDER BY created_at DESC LIMIT :l"), {"l": limit})
        rows = res.fetchall()
        return [dict(r) for r in rows]

@app.post("/alerts/{alert_id}/ack", dependencies=[Depends(authorize)])
async def ack_alert(alert_id: str):
    async with AsyncSessionLocal() as session:
        await session.execute(text("UPDATE alerts SET acknowledged = TRUE WHERE id = :id"), {"id": alert_id})
        await session.commit()
    return {"status": "acknowledged"}



README.md (short)
# Defensive 24/7 Monitor — Starter

This is a lawful, defensive starter system for collecting telemetry, running simple detection rules, and issuing alerts for human review.

## Run locally (development)

1. Copy `.env.example` to `.env` and fill values.
2. Build & run:


docker-compose up –build
3. Initialize DB once:


docker exec -it <db_container_name> psql -U postgres -d monitor -f /usr/src/app/init_db.sql
or use the provided init_db.sql from the host.

4. Ingest example event:


curl -X POST http://localhost:8000/ingest -H “X-API-Key: <API_KEY>” -H “Content-Type: application/json” -d ‘{“source”:“app”,“event_type”:“auth”,“payload”:{“action”:“login_failed”,“account”:“alice”,“ip”:“1.2.3.4”}}’
5. View alerts:
curl -H “X-API-Key: <API_KEY>” http://localhost:8000/alerts
## Important
- This project is read-only: it only detects and alerts. **No enforcement (freezing, transfers, or blocking) is performed automatically.**
- Comply with all legal and privacy requirements before deploying. If you need to add enforcement, ensure you have documented legal authority and human approvals.

How this protects against abuse and what to not do
	•	This code does not include any ability to freeze bank accounts, extract private keys, or deanonymize users. It solely collects telemetry and surfaces suspicious events to human operators.
	•	If you want to extend to automated blocking of compromised accounts, add strict governance: multi-person approval, auditable logs, legal signoff — and implement such actions in a separate service that is only invoked after human authorization.
	•	NEVER ingest private data from other parties without their consent. Follow GDPR, CCPA, and other local laws.

⸻

Next steps you can request (safe)

If you want, I can:
	•	Provide a tested docker exec script to initialize the DB and seed sample events and alerts.
	•	Add an example front-end dashboard (React) for viewing alerts (read-only) with ack/resolve actions.
	•	Add support for Redis/queueing (RabitMQ/Celery) for larger scale ingestion.
	•	Show how to integrate with Suricata/Zeek or a commercial EDR in a defensive way (only guidance, not offensive tools).
	•	Provide sample unit tests and CI pipeline for this repo.









