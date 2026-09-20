# Secure Cloud API - SQL Injection Defence & Data-Leak Detection

A lightweight cloud-ready REST API that protects user data against SQL injection using a
**double-layer security protocol**, **AES-256-GCM** encryption at rest and a **capability-code mechanism**
that controls which SQL each caller may execute. Runs in ~50 MB of RAM (Flask + SQLite + one gunicorn worker).

## Architecture

```
Internet --HTTPS--> [ TLS proxy / load balancer ]
                          |
        +-----------------v------------------+
        | LAYER 1 - gateway guard (app/guard) |
        |  - request size cap, rate limit      |
        |  - SQLi pattern detector (+ logging) |
        |  - strict allow-list validation      |
        |  - capability token check (route)    |
        +-----------------+------------------+
                          |  only clean, typed values
        +-----------------v------------------+
        | LAYER 2 - data layer (app/db)        |
        |  - query CATALOG: no raw SQL, ever   |
        |  - capability check per query        |
        |  - param count/type check, ? binding |
        |  - SQLite authoriser (least privilege)|
        |  - AES-256-GCM encrypted columns     |
        +-----------------+------------------+
                          v
                    SQLite / RDS
```

| Task requirement | Implementation |
|---|---|
| Cloud system securing user data against SQLi | Flask API + Dockerfile, deployable on any VM/PaaS |
| AES-256 for credentials & sensitive info | `app/crypto.py`: AES-256-GCM, random nonce, column-bound AAD. Password = scrypt hash, then AES-256 encrypted |
| Capability code mechanism (inject SQL securely, control server access) | `app/queries.py` + `app/db.py` (named parameterised statements, each needing a capability) and `app/capabilities.py` (signed, expiring tokens) |
| Double-layer protocol | Layer 1 `app/guard.py` + Layer 2 `app/db.py`; either one alone stops the tested attacks |
| Accessible over the internet, light requirements | Single container, 1 worker, SQLite, stdlib + 3 small packages |
| Detecting leaks / attacks | `security_events` table, readable by admins at `/admin/security-events` |

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export $(python scripts/gen_keys.py | xargs)            # Windows: set the two variables manually
python -m gunicorn -b 127.0.0.1:8000 wsgi:app           # Windows: use `flask --app wsgi run`
python -m unittest discover -s tests -v                 # 24 tests
```

Create an admin (admins can't self-register): `python scripts/create_admin.py root root@example.com`

## API

| Method & path | Capability | Notes |
|---|---|---|
| `POST /register` | public | `username, email, password, phone?` |
| `POST /login` | public | returns a 15-minute capability token |
| `GET /profile` | `profile:read` | decrypted email/phone of the token owner only |
| `PUT /profile` | `profile:write` | update own email/phone |
| `GET /admin/users?prefix=` | `users:search` | admin only |
| `GET /admin/security-events` | `audit:read` | admin only |

```bash
curl -X POST $URL/register -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.com","password":"Str0ng-Pa55word!"}'
TOKEN=$(curl -s -X POST $URL/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Str0ng-Pa55word!"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl $URL/profile -H "Authorization: Bearer $TOKEN"
```

## Deploy so it is reachable from the internet

### Option A - AWS EC2 / Lightsail (small instance, e.g. t3.micro or the smallest Lightsail plan)

```bash
# on the server (Ubuntu)
sudo apt update && sudo apt install -y docker.io git
git clone https://github.com/<you>/secure-sqli-shield.git && cd secure-sqli-shield
python3 scripts/gen_keys.py > .env && echo "TRUST_PROXY=1" >> .env
sudo docker build -t secure-api .
sudo docker run -d --name api --restart unless-stopped --env-file .env \
     -v /opt/secure-data:/data -p 127.0.0.1:8000:8000 secure-api
```
Open ports 80/443 only (security group / Lightsail firewall) and put HTTPS in front with Caddy
(automatic Let's Encrypt; point a domain's A record at the server first):

```bash
sudo apt install -y caddy
echo 'your-domain.com { reverse_proxy 127.0.0.1:8000 }' | sudo tee /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

### Option B - PaaS (Render, Railway, Fly.io)
Push to GitHub, create a *Web Service* from the repo (Docker), add `APP_ENC_KEY`, `APP_TOKEN_KEY` and
`TRUST_PROXY=1` as environment variables. HTTPS is provided automatically. Check the platform's disk policy:
SQLite needs a persistent volume, otherwise use RDS/managed Postgres.

## Production hardening notes

* Keep the keys in AWS Secrets Manager / SSM Parameter Store (or use KMS envelope encryption), never in git.
  Rotate by adding a `v2:` ciphertext version (the `v1:` prefix is already there for this).
* SQLite is right for a small, single-node deployment. For scale, swap `SecureDB` for PostgreSQL (RDS) with a
  DB role that only has SELECT/INSERT/UPDATE on these two tables. The catalog + capability design stays the same.
* The rate limiter is in-process. Behind several instances use AWS WAF (it ships managed SQLi rule sets) or Redis.
* Layer 1's pattern detector is a *detection/logging* control and can be evaded; the guarantees come from
  allow-list validation and Layer 2 (parameter binding + authoriser). That is why both layers exist.
