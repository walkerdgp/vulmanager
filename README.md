# 🛡️ VulnManager - Vulnerability Management Platform

Enterprise-grade, open-source vulnerability management platform inspired by [Faraday](https://github.com/infobyte/faraday) and [Módulo Risk Manager](https://www.modulo.com.br/).

## ✨ Features (Phase 1 - Foundation)

| Feature | Status |
|---------|--------|
| PostgreSQL database (multi-tenant) | ✅ |
| Flask REST API with full CRUD | ✅ |
| RBAC: Admin, Analyst, Viewer roles | ✅ |
| Multi-tenant isolation per client | ✅ |
| LDAP/AD integration ready | ✅ |
| Web dashboard with advanced filters | ✅ |
| Filters: date range, CVE, severity, host type, scanner | ✅ |
| PDF export with active filters | ✅ |
| Webhook inbound API (scanner import) | ✅ |
| Docker Compose deployment | ✅ |
| Responsive UI (mobile + desktop) | ✅ |

## 🚀 Quick Start

### Option 1: Docker (Recommended)
```bash
git clone https://github.com/youruser/vulnmanager.git
cd vulnmanager
chmod +x scripts/setup.sh
sudo ./scripts/setup.sh
```

### Option 2: Local Install (Ubuntu 22.04)
```bash
sudo ./scripts/setup.sh --local
```

### Option 3: Manual Development
```bash
# Install PostgreSQL and Redis first, then:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your database credentials

export FLASK_APP=run.py
flask init-db
flask seed-db
python run.py
```

**Open:** http://localhost:5000

**Demo Accounts:**
| User | Password | Role |
|------|----------|------|
| admin | admin123 | Superadmin (all tenants) |
| analyst | analyst123 | Analyst (CRUD vulns, run scans) |
| viewer | viewer123 | Viewer (read-only) |

---

## 📡 REST API

Base URL: `http://localhost:5000/api/v1`

### Authentication
All API endpoints accept:
- **Session cookie** (from web login)
- **API Key**: `X-API-Key: your-api-key` header

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/workspaces` | List workspaces |
| POST | `/workspaces` | Create workspace |
| GET | `/hosts` | List hosts (with filters) |
| POST | `/hosts` | Create/update host (upsert) |
| GET | `/vulnerabilities` | List vulns (with filters) |
| POST | `/vulnerabilities` | Create vulnerability |
| PATCH | `/vulnerabilities/<id>` | Update vuln status |
| GET | `/scans` | List scans |
| POST | `/scans` | Register scan |
| POST | `/webhook/inbound` | Import scan results (bulk) |

### Filter Parameters (GET /vulnerabilities)
```
?severity=critical
?status=open
?cve=CVE-2021-44228
?host_type=server
?scanner=openvas
?date_from=2024-01-01
?date_to=2024-12-31
?host_ip=10.0.1.10
?page=1&per_page=50
```

### Webhook Import Example
Push scan results from any tool:
```bash
curl -X POST http://localhost:5000/api/v1/webhook/inbound \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "openvas",
    "workspace_id": 1,
    "hosts": [
      {
        "ip": "192.168.1.100",
        "hostname": "web-server",
        "os": "Ubuntu 22.04",
        "services": [
          {"port": 80, "protocol": "tcp", "name": "http", "version": "nginx/1.24"}
        ],
        "vulnerabilities": [
          {
            "title": "Outdated nginx version",
            "cve_id": "CVE-2023-44487",
            "severity": "high",
            "cvss_score": 7.5,
            "description": "HTTP/2 rapid reset vulnerability",
            "solution": "Upgrade nginx to 1.25.3+"
          }
        ]
      }
    ]
  }'
```

---

## 🏗️ Architecture

```
vulnmanager/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── models/              # SQLAlchemy models (multi-tenant)
│   ├── routes/
│   │   ├── auth.py          # Login/logout/LDAP
│   │   ├── dashboard.py     # Web UI with filters
│   │   ├── api.py           # REST API v1
│   │   └── export.py        # PDF export
│   ├── services/
│   │   └── seeder.py        # Demo data generator
│   └── templates/           # Jinja2 HTML templates
├── config/
│   └── settings.py          # App configuration
├── scripts/
│   └── setup.sh             # Auto-install script
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── run.py                   # Entry point
```

### Database Schema
```
tenants ──< workspaces ──< hosts ──< vulnerabilities
                │                        │
                └──< scans ──────────────┘

users ──< tenant_users (RBAC: admin/analyst/viewer)
```

---

## 🔮 Roadmap

### Phase 2 - Integrations
- [ ] LDAP/AD with group-to-role mapping
- [ ] OpenVAS/GVM connector
- [ ] Nessus connector
- [ ] Nmap auto-scanner
- [ ] ZAP Proxy connector
- [ ] Outbound webhooks

### Phase 3 - Advanced
- [ ] Burp Suite & Caido connectors
- [ ] Custom CLI tool runner
- [ ] Scheduled scans (cron)
- [ ] Email notifications
- [ ] PCI-DSS / ISO 27001 compliance
- [ ] Risk scoring engine
- [ ] SLA tracking

### Phase 4 - Enterprise
- [ ] SAML SSO
- [ ] Full audit logging
- [ ] Jira/ServiceNow integration
- [ ] Threat intelligence feeds
- [ ] Kubernetes deployment

---

## 📋 Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.10+ / Flask |
| Database | PostgreSQL 16 |
| ORM | SQLAlchemy + Alembic |
| Auth | Flask-Login + LDAP3 |
| API | Flask-RESTful + Marshmallow |
| Frontend | Tailwind CSS + Alpine.js |
| Charts | Chart.js |
| PDF | WeasyPrint |
| Queue | Celery + Redis |
| Deploy | Docker Compose |
| Target OS | Ubuntu 22.04 LTS |

---

## 🔒 Security Notes

- Change all default passwords before production
- Use HTTPS (nginx + Let's Encrypt)
- Set a strong `SECRET_KEY` in `.env`
- Restrict API access with API keys
- Configure firewall (UFW) to limit exposed ports
- LDAP bind credentials should use a read-only account

## License

MIT - Open Source
