"""
REST API v1 - External integrations, webhooks, CRUD
All endpoints require API key or session auth.
"""
from datetime import datetime, timezone
from functools import wraps
from flask import Blueprint, request, jsonify, session
from flask_login import current_user
from app.models import (
    db, User, Tenant, TenantUser, ApiKey, Workspace,
    Host, Service, Vulnerability, Scan, Webhook, bcrypt
)

api_bp = Blueprint('api', __name__)


# ============================================================
# AUTH MIDDLEWARE
# ============================================================

def api_auth_required(f):
    """Authenticate via API key header or session cookie."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check API key first
        api_key = request.headers.get('X-API-Key')
        if api_key:
            prefix = api_key[:8]
            key_record = ApiKey.query.filter_by(prefix=prefix, is_active=True).first()
            if key_record and bcrypt.check_password_hash(key_record.key_hash, api_key):
                key_record.last_used = datetime.now(timezone.utc)
                db.session.commit()
                request.api_user = User.query.get(key_record.user_id)
                request.api_tenant_id = key_record.tenant_id
                return f(*args, **kwargs)
            return jsonify({'error': 'Invalid API key'}), 401

        # Fall back to session auth
        if current_user.is_authenticated:
            request.api_user = current_user
            request.api_tenant_id = session.get('current_tenant_id')
            if not request.api_tenant_id:
                return jsonify({'error': 'No tenant selected'}), 400
            return f(*args, **kwargs)

        return jsonify({'error': 'Authentication required'}), 401
    return decorated


def require_role(*roles):
    """Check user has required role in current tenant."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = request.api_user
            tenant_id = request.api_tenant_id
            if user.is_superadmin:
                return f(*args, **kwargs)
            tu = TenantUser.query.filter_by(
                user_id=user.id, tenant_id=tenant_id
            ).first()
            if not tu or tu.role not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ============================================================
# HEALTH CHECK
# ============================================================

@api_bp.route('/health')
def health():
    return jsonify({'status': 'ok', 'version': '1.0.0'})


# ============================================================
# HOSTS (INVENTORY)
# ============================================================

@api_bp.route('/hosts', methods=['GET'])
@api_auth_required
def list_hosts():
    """List hosts with filters. Supports external inventory sync."""
    tenant_id = request.api_tenant_id
    workspace_ids = [w.id for w in Workspace.query.filter_by(
        tenant_id=tenant_id, is_active=True
    ).all()]

    query = Host.query.filter(Host.workspace_id.in_(workspace_ids))

    # Filters
    host_type = request.args.get('host_type')
    if host_type:
        query = query.filter(Host.host_type == host_type)

    status = request.args.get('status')
    if status:
        query = query.filter(Host.status == status)

    search = request.args.get('q')
    if search:
        query = query.filter(
            db.or_(
                Host.ip_address.ilike(f'%{search}%'),
                Host.hostname.ilike(f'%{search}%'),
            )
        )

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    pagination = query.paginate(page=page, per_page=min(per_page, 200))

    hosts_data = [{
        'id': h.id,
        'ip_address': h.ip_address,
        'hostname': h.hostname,
        'mac_address': h.mac_address,
        'os_name': h.os_name,
        'os_version': h.os_version,
        'host_type': h.host_type,
        'status': h.status,
        'owner': h.owner,
        'location': h.location,
        'tags': h.tags,
        'vuln_count': h.vuln_count,
        'first_seen': h.first_seen.isoformat() if h.first_seen else None,
        'last_seen': h.last_seen.isoformat() if h.last_seen else None,
    } for h in pagination.items]

    return jsonify({
        'data': hosts_data,
        'pagination': {
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total': pagination.total,
            'pages': pagination.pages,
        }
    })


@api_bp.route('/hosts', methods=['POST'])
@api_auth_required
@require_role('admin', 'analyst')
def create_host():
    """Create or update a host (upsert by IP within workspace)."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    workspace_id = data.get('workspace_id')
    ip_address = data.get('ip_address')
    if not workspace_id or not ip_address:
        return jsonify({'error': 'workspace_id and ip_address required'}), 400

    # Verify workspace belongs to tenant
    ws = Workspace.query.filter_by(
        id=workspace_id, tenant_id=request.api_tenant_id
    ).first()
    if not ws:
        return jsonify({'error': 'Workspace not found'}), 404

    # Upsert
    host = Host.query.filter_by(
        workspace_id=workspace_id, ip_address=ip_address
    ).first()

    if host:
        # Update existing
        for field in ['hostname', 'mac_address', 'os_name', 'os_version',
                      'host_type', 'status', 'owner', 'location', 'notes', 'tags']:
            if field in data:
                setattr(host, field, data[field])
        host.last_seen = datetime.now(timezone.utc)
    else:
        # Create new
        host = Host(
            workspace_id=workspace_id,
            ip_address=ip_address,
            hostname=data.get('hostname'),
            mac_address=data.get('mac_address'),
            os_name=data.get('os_name'),
            os_version=data.get('os_version'),
            host_type=data.get('host_type', 'server'),
            status=data.get('status', 'active'),
            owner=data.get('owner'),
            location=data.get('location'),
            notes=data.get('notes'),
            tags=data.get('tags', []),
        )
        db.session.add(host)

    db.session.commit()
    return jsonify({
        'id': host.id,
        'ip_address': host.ip_address,
        'message': 'Host created/updated'
    }), 201


# ============================================================
# VULNERABILITIES
# ============================================================

@api_bp.route('/vulnerabilities', methods=['GET'])
@api_auth_required
def list_vulnerabilities():
    """List vulnerabilities with full filter support."""
    tenant_id = request.api_tenant_id
    workspace_ids = [w.id for w in Workspace.query.filter_by(
        tenant_id=tenant_id, is_active=True
    ).all()]

    query = Vulnerability.query.join(Host).filter(
        Host.workspace_id.in_(workspace_ids)
    )

    # Filters
    severity = request.args.get('severity')
    if severity:
        query = query.filter(Vulnerability.severity == severity)

    status = request.args.get('status')
    if status:
        query = query.filter(Vulnerability.status == status)

    cve = request.args.get('cve')
    if cve:
        query = query.filter(Vulnerability.cve_id.ilike(f'%{cve}%'))

    host_type = request.args.get('host_type')
    if host_type:
        query = query.filter(Host.host_type == host_type)

    scanner = request.args.get('scanner')
    if scanner:
        query = query.filter(Vulnerability.scanner == scanner)

    date_from = request.args.get('date_from')
    if date_from:
        try:
            dt = datetime.strptime(date_from, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            query = query.filter(Vulnerability.created_at >= dt)
        except ValueError:
            pass

    date_to = request.args.get('date_to')
    if date_to:
        try:
            dt = datetime.strptime(date_to, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            query = query.filter(Vulnerability.created_at <= dt)
        except ValueError:
            pass

    host_ip = request.args.get('host_ip')
    if host_ip:
        query = query.filter(Host.ip_address == host_ip)

    query = query.order_by(Vulnerability.created_at.desc())

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    pagination = query.paginate(page=page, per_page=min(per_page, 200))

    vulns_data = [{
        'id': v.id,
        'title': v.title,
        'cve_id': v.cve_id,
        'cwe_id': v.cwe_id,
        'severity': v.severity,
        'cvss_score': v.cvss_score,
        'status': v.status,
        'host_ip': v.host.ip_address,
        'host_hostname': v.host.hostname,
        'host_type': v.host.host_type,
        'scanner': v.scanner,
        'description': v.description,
        'solution': v.solution,
        'assigned_to': v.assigned_to,
        'due_date': v.due_date.isoformat() if v.due_date else None,
        'created_at': v.created_at.isoformat(),
    } for v in pagination.items]

    return jsonify({
        'data': vulns_data,
        'pagination': {
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total': pagination.total,
            'pages': pagination.pages,
        }
    })


@api_bp.route('/vulnerabilities', methods=['POST'])
@api_auth_required
@require_role('admin', 'analyst')
def create_vulnerability():
    """Create a vulnerability (used by scanner integrations)."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    host_id = data.get('host_id')
    title = data.get('title')
    if not host_id or not title:
        return jsonify({'error': 'host_id and title required'}), 400

    # Verify host belongs to tenant
    host = Host.query.get(host_id)
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    ws = Workspace.query.filter_by(
        id=host.workspace_id, tenant_id=request.api_tenant_id
    ).first()
    if not ws:
        return jsonify({'error': 'Access denied'}), 403

    vuln = Vulnerability(
        host_id=host_id,
        scan_id=data.get('scan_id'),
        title=title,
        cve_id=data.get('cve_id'),
        cwe_id=data.get('cwe_id'),
        external_id=data.get('external_id'),
        severity=data.get('severity', 'info'),
        cvss_score=data.get('cvss_score'),
        cvss_vector=data.get('cvss_vector'),
        description=data.get('description'),
        solution=data.get('solution'),
        references=data.get('references', []),
        evidence=data.get('evidence'),
        affected_component=data.get('affected_component'),
        scanner=data.get('scanner', 'api'),
        tool_output=data.get('tool_output'),
        tags=data.get('tags', []),
    )
    db.session.add(vuln)
    db.session.commit()

    return jsonify({'id': vuln.id, 'message': 'Vulnerability created'}), 201


@api_bp.route('/vulnerabilities/<int:vuln_id>', methods=['PATCH'])
@api_auth_required
@require_role('admin', 'analyst')
def update_vulnerability(vuln_id):
    """Update vulnerability status/details."""
    vuln = Vulnerability.query.get_or_404(vuln_id)
    data = request.get_json()

    updatable = ['status', 'severity', 'assigned_to', 'due_date',
                 'solution', 'tags', 'description']
    for field in updatable:
        if field in data:
            setattr(vuln, field, data[field])

    if 'status' in data and data['status'] == 'resolved':
        vuln.resolved_at = datetime.now(timezone.utc)

    db.session.commit()
    return jsonify({'id': vuln.id, 'message': 'Updated'})


# ============================================================
# SCANS
# ============================================================

@api_bp.route('/scans', methods=['GET'])
@api_auth_required
def list_scans():
    tenant_id = request.api_tenant_id
    workspace_ids = [w.id for w in Workspace.query.filter_by(
        tenant_id=tenant_id, is_active=True
    ).all()]

    scans = Scan.query.filter(
        Scan.workspace_id.in_(workspace_ids)
    ).order_by(Scan.created_at.desc()).limit(100).all()

    return jsonify({'data': [{
        'id': s.id,
        'name': s.name,
        'scanner': s.scanner,
        'scan_type': s.scan_type,
        'target': s.target,
        'status': s.status,
        'host_count': s.host_count,
        'vuln_count': s.vuln_count,
        'started_at': s.started_at.isoformat() if s.started_at else None,
        'completed_at': s.completed_at.isoformat() if s.completed_at else None,
    } for s in scans]})


@api_bp.route('/scans', methods=['POST'])
@api_auth_required
@require_role('admin', 'analyst')
def create_scan():
    """Register a scan (for importing results from external tools)."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    workspace_id = data.get('workspace_id')
    ws = Workspace.query.filter_by(
        id=workspace_id, tenant_id=request.api_tenant_id
    ).first()
    if not ws:
        return jsonify({'error': 'Workspace not found'}), 404

    scan = Scan(
        workspace_id=workspace_id,
        name=data.get('name', f'Scan {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")}'),
        scanner=data.get('scanner', 'manual'),
        scan_type=data.get('scan_type', 'custom'),
        target=data.get('target'),
        status=data.get('status', 'completed'),
        started_at=data.get('started_at'),
        completed_at=data.get('completed_at'),
        host_count=data.get('host_count', 0),
        vuln_count=data.get('vuln_count', 0),
        launched_by=request.api_user.username,
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify({'id': scan.id, 'message': 'Scan registered'}), 201


# ============================================================
# WORKSPACES
# ============================================================

@api_bp.route('/workspaces', methods=['GET'])
@api_auth_required
def list_workspaces():
    tenant_id = request.api_tenant_id
    workspaces = Workspace.query.filter_by(
        tenant_id=tenant_id, is_active=True
    ).all()

    return jsonify({'data': [{
        'id': w.id,
        'name': w.name,
        'description': w.description,
        'created_at': w.created_at.isoformat(),
    } for w in workspaces]})


@api_bp.route('/workspaces', methods=['POST'])
@api_auth_required
@require_role('admin')
def create_workspace():
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({'error': 'name required'}), 400

    ws = Workspace(
        tenant_id=request.api_tenant_id,
        name=data['name'],
        description=data.get('description'),
    )
    db.session.add(ws)
    db.session.commit()
    return jsonify({'id': ws.id, 'message': 'Workspace created'}), 201


# ============================================================
# WEBHOOK INBOUND (receive data from external tools)
# ============================================================

@api_bp.route('/webhook/inbound', methods=['POST'])
@api_auth_required
@require_role('admin', 'analyst')
def webhook_inbound():
    """
    Generic webhook endpoint for receiving scan results.
    Expected format:
    {
        "source": "openvas|nessus|nmap|zap|burp|caido|custom",
        "workspace_id": 1,
        "hosts": [
            {
                "ip": "192.168.1.1",
                "hostname": "web-server",
                "os": "Ubuntu 22.04",
                "services": [{"port": 80, "protocol": "tcp", "name": "http"}],
                "vulnerabilities": [
                    {
                        "title": "...",
                        "cve_id": "CVE-2023-XXXX",
                        "severity": "high",
                        "cvss_score": 8.5,
                        "description": "...",
                        "solution": "..."
                    }
                ]
            }
        ]
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    workspace_id = data.get('workspace_id')
    source = data.get('source', 'webhook')
    hosts_data = data.get('hosts', [])

    ws = Workspace.query.filter_by(
        id=workspace_id, tenant_id=request.api_tenant_id
    ).first()
    if not ws:
        return jsonify({'error': 'Workspace not found'}), 404

    # Create scan record
    scan = Scan(
        workspace_id=workspace_id,
        name=f'Webhook import from {source}',
        scanner=source,
        scan_type='import',
        status='completed',
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        launched_by=request.api_user.username,
    )
    db.session.add(scan)
    db.session.flush()

    host_count = 0
    vuln_count = 0

    for host_data in hosts_data:
        ip = host_data.get('ip')
        if not ip:
            continue

        # Upsert host
        host = Host.query.filter_by(
            workspace_id=workspace_id, ip_address=ip
        ).first()
        if not host:
            host = Host(workspace_id=workspace_id, ip_address=ip)
            db.session.add(host)

        host.hostname = host_data.get('hostname', host.hostname)
        host.os_name = host_data.get('os', host.os_name)
        host.last_seen = datetime.now(timezone.utc)
        db.session.flush()
        host_count += 1

        # Services
        for svc_data in host_data.get('services', []):
            svc = Service.query.filter_by(
                host_id=host.id,
                port=svc_data['port'],
                protocol=svc_data.get('protocol', 'tcp')
            ).first()
            if not svc:
                svc = Service(
                    host_id=host.id,
                    port=svc_data['port'],
                    protocol=svc_data.get('protocol', 'tcp'),
                )
                db.session.add(svc)
            svc.service_name = svc_data.get('name', svc.service_name)
            svc.version = svc_data.get('version', svc.version)

        # Vulnerabilities
        for vuln_data in host_data.get('vulnerabilities', []):
            vuln = Vulnerability(
                host_id=host.id,
                scan_id=scan.id,
                title=vuln_data.get('title', 'Unnamed'),
                cve_id=vuln_data.get('cve_id'),
                cwe_id=vuln_data.get('cwe_id'),
                severity=vuln_data.get('severity', 'info'),
                cvss_score=vuln_data.get('cvss_score'),
                cvss_vector=vuln_data.get('cvss_vector'),
                description=vuln_data.get('description'),
                solution=vuln_data.get('solution'),
                references=vuln_data.get('references', []),
                evidence=vuln_data.get('evidence'),
                scanner=source,
                tool_output=vuln_data.get('tool_output'),
            )
            db.session.add(vuln)
            vuln_count += 1

    scan.host_count = host_count
    scan.vuln_count = vuln_count
    db.session.commit()

    return jsonify({
        'scan_id': scan.id,
        'hosts_processed': host_count,
        'vulns_imported': vuln_count,
        'message': 'Import successful'
    }), 201
