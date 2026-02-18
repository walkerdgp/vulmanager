#!/bin/bash
# ============================================================
# VulnManager - Installation Script for Ubuntu 22.04 LTS
# ============================================================
# Usage:
#   chmod +x scripts/setup.sh
#   sudo ./scripts/setup.sh         # Full install with Docker
#   sudo ./scripts/setup.sh --local  # Local install without Docker
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     VulnManager - Setup Script           ║"
echo "║     Vulnerability Management Platform    ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ============================================================
# OPTION 1: DOCKER DEPLOYMENT (recommended)
# ============================================================
docker_install() {
    info "Installing with Docker Compose..."

    # Install Docker if not present
    if ! command -v docker &> /dev/null; then
        log "Installing Docker..."
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker $SUDO_USER 2>/dev/null || true
        sudo systemctl enable docker
        sudo systemctl start docker
    else
        log "Docker already installed."
    fi

    # Install Docker Compose plugin if not present
    if ! docker compose version &> /dev/null; then
        log "Installing Docker Compose plugin..."
        sudo apt-get install -y docker-compose-plugin
    else
        log "Docker Compose already installed."
    fi

    # Create .env from example
    if [ ! -f .env ]; then
        cp .env.example .env
        # Generate random secret key
        SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        sed -i "s/CHANGE-ME-TO-RANDOM-64-CHARS/$SECRET/" .env
        DB_PASS=$(python3 -c "import secrets; print(secrets.token_hex(16))")
        echo "DB_PASSWORD=$DB_PASS" >> .env
        log "Created .env with secure defaults"
    else
        warn ".env already exists, skipping"
    fi

    # Build and start
    log "Building and starting containers..."
    docker compose up -d --build

    # Wait for DB
    info "Waiting for database to be ready..."
    sleep 5

    # Initialize database and seed demo data
    log "Initializing database..."
    docker compose exec web flask init-db
    docker compose exec web flask seed-db

    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║  ✓ VulnManager is running!               ║"
    echo "║                                          ║"
    echo "║  URL:  http://localhost:5000              ║"
    echo "║                                          ║"
    echo "║  Demo Accounts:                          ║"
    echo "║    admin   / admin123    (superadmin)     ║"
    echo "║    analyst / analyst123  (analyst role)   ║"
    echo "║    viewer  / viewer123   (read-only)      ║"
    echo "║                                          ║"
    echo "║  API: http://localhost:5000/api/v1/health ║"
    echo "╚══════════════════════════════════════════╝"
}

# ============================================================
# OPTION 2: LOCAL INSTALL (no Docker)
# ============================================================
local_install() {
    info "Installing locally on Ubuntu 22.04..."

    # System packages
    log "Installing system dependencies..."
    sudo apt-get update
    sudo apt-get install -y \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib \
        redis-server \
        libpq-dev libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 libffi-dev shared-mime-info \
        nmap \
        nginx

    # PostgreSQL setup
    log "Configuring PostgreSQL..."
    sudo -u postgres psql -c "CREATE USER vulnmanager WITH PASSWORD 'vulnmanager';" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE DATABASE vulnmanager OWNER vulnmanager;" 2>/dev/null || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE vulnmanager TO vulnmanager;" 2>/dev/null || true

    # Enable and start services
    sudo systemctl enable postgresql redis-server
    sudo systemctl start postgresql redis-server

    # Python virtual environment
    log "Setting up Python environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt

    # Create .env
    if [ ! -f .env ]; then
        cp .env.example .env
        SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        sed -i "s/CHANGE-ME-TO-RANDOM-64-CHARS/$SECRET/" .env
        log "Created .env file"
    fi

    # Initialize database
    log "Initializing database..."
    export FLASK_APP=run.py
    flask init-db
    flask seed-db

    # Create systemd service
    log "Creating systemd service..."
    sudo tee /etc/systemd/system/vulnmanager.service > /dev/null << EOF
[Unit]
Description=VulnManager Web Application
After=network.target postgresql.service redis-server.service

[Service]
Type=simple
User=$SUDO_USER
WorkingDirectory=$(pwd)
Environment="PATH=$(pwd)/venv/bin"
ExecStart=$(pwd)/venv/bin/gunicorn run:app -b 127.0.0.1:5000 -w 4 --timeout 120
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable vulnmanager
    sudo systemctl start vulnmanager

    # Nginx reverse proxy
    log "Configuring Nginx..."
    sudo tee /etc/nginx/sites-available/vulnmanager > /dev/null << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static {
        alias /opt/vulnmanager/app/static;
        expires 30d;
    }
}
EOF

    sudo ln -sf /etc/nginx/sites-available/vulnmanager /etc/nginx/sites-enabled/
    sudo rm -f /etc/nginx/sites-enabled/default
    sudo nginx -t && sudo systemctl restart nginx

    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║  ✓ VulnManager installed locally!        ║"
    echo "║                                          ║"
    echo "║  URL:  http://$(hostname -I | awk '{print $1}')              ║"
    echo "║                                          ║"
    echo "║  Service: sudo systemctl status vulnmanager ║"
    echo "║  Logs:    journalctl -u vulnmanager -f    ║"
    echo "╚══════════════════════════════════════════╝"
}

# ============================================================
# RUN
# ============================================================
if [ "$1" == "--local" ]; then
    local_install
else
    docker_install
fi
