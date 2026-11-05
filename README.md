$readme_text = @'
# Aegis Ledger: Active Defense and Threat Intelligence Pipeline

Aegis Ledger is a zero-trust, microservice-based security pipeline designed for small to medium-sized businesses (SMBs). It moves beyond passive blocking by actively deceiving attackers with believable fake data while collecting threat intelligence.

## Problem Statement

Enterprise deception platforms (such as Acalvio or Thinkst Canary) are highly effective but typically cost tens of thousands of dollars annually. This creates a significant security gap for smaller organizations and independent developers. Aegis Ledger provides a lightweight, open-source alternative that deploys deception mechanisms, behavioral analysis, and LLM-driven payload auditing.

## Core Architecture

The system is built on a zero-trust model, isolated within Docker networks:
- **Internal Network:** Houses PostgreSQL, Redis, the API, and the Worker. No external egress.
- **Egress Network:** Attached only to the Worker for LLM API calls.
- **Edge Network:** Attached to the Next.js frontend.

### Key Security Features

1. **Deception Gate:** When the API detects a hostile signature (e.g., SQL Injection), it does not return a 403 error. Instead, it routes the request to a honeypot and returns a believable, dynamically generated fake response (fake UUID, fake hash) to the attacker.
2. **Canary Tokens:** Embedded within decoy data. If an attacker attempts to use these tokens in subsequent requests, the system triggers a critical alert.
3. **Redis Tarpit:** Behavioral analysis. If an IP sends multiple suspicious requests within a short timeframe, the system introduces artificial delays (Tarpit) to waste the attacker's time and resources.
4. **LLM Auditor:** An asynchronous worker evaluates payloads using strict schema validation and prompt-injection guardrails, returning structured threat intelligence.
5. **BFF Proxy:** The Next.js frontend communicates through a Backend-For-Frontend proxy, ensuring API keys are never exposed to the browser.

## Technology Stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy (Async), PostgreSQL, Redis.
- **Frontend:** Next.js 15, React, Tailwind CSS, TypeScript.
- **Infrastructure:** Docker, Docker Compose.

## Deployment

### Prerequisites
- Docker and Docker Compose installed.

### Setup

1. Clone the repository and navigate to the project directory.
2. Create the environment file:
   ```bash
   cp .env.example .env 

3. Generate secure secrets for .env (PostgreSQL password, Redis password, and console token).

4. Build and start the infrastructure:

   bash

   docker compose up -d --build 

5. Access the console at http://localhost:3000