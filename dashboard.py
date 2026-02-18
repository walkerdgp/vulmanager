"""
Dashboard routes - Main web interface with filtering
"""
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, request, session, abort
from flask_login import login_required, current_user
from sqlalchemy import func, and_
from app.models import (
    db, Tenant, TenantUser, Workspace, Host, Vulnerability, Scan, Service
)

dashboard_bp = Blueprint('dashboard', __name__)


def get_current_tenant():
    """Get the active tenant from session, enforce access."""
    tenant_id = session.get('current_tenant_id')
    if not tenant_id:
        # Try to get first available tenant
        if current_user.is_superadmin:
            tenant = Tenant.query.first()
        else:
            tu = TenantUser.query.filter_by(user_id=current_user.id).first()
            tenant = tu.tenant if tu else None
        if tenant:
            session['current_tenant_id'] = tenant.id
            return tenant
        return None

    # Verify access
    if current_user.is_superadmin:
        return Tenant.query.get(tenant_id)

    tu = TenantUser.query.filter_by(
        user_id=current_user.id, tenant_id=tenant_id
    ).first()
    return tu.tenant if tu else None


def get_user_role(tenant_id):
    """Get the current user's role for the active tenant."""
    if current_user.is_superadmin:
        return 'admin'
    tu = TenantUser.query.filter_by(
        user_id=current_user.id, tenant_id=tenant_id
    ).first()
    return tu.role if tu else None


@dashboard_bp.route('/')
@login_required
def index():
    """Main dashboard with KPIs and charts."""
    tenant = get_current_tenant()
    if not tenant:
        return render_template('dashboard/no_tenant.html')

    role = get_user_role(tenant.id)
    workspace_ids = [w.id for w in Workspace.query.filter_by(
        tenant_id=tenant.id, is_active=True
    ).all()]

    # KPIs
    total_hosts = Host.query.filter(Host.workspace_id.in_(workspace_ids)).count()
    total_vulns = Vulnerability.query.join(Host).filter(
        Host.workspace_id.in_(workspace_ids)
    ).count()
    open_vulns = Vulnerability.query.join(Host).filter(
        Host.workspace_id.in_(workspace_ids),
        Vulnerability.status.in_(['open', 'confirmed'])
    ).count()
    critical_vulns = Vulnerability.query.join(Host).filter(
        Host.workspace_id.in_(workspace_ids),
        Vulnerability.severity == 'critical',
        Vulnerability.status.in_(['open', 'confirmed'])
    ).count()

    # Severity breakdown
    severity_counts = db.session.query(
        Vulnerability.severity, func.count(Vulnerability.id)
    ).join(Host).filter(
        Host.workspace_id.in_(workspace_ids),
        Vulnerability.status.in_(['open', 'confirmed', 'in_progress'])
    ).group_by(Vulnerability.severity).all()

    severity_data = {s: c for s, c in severity_counts}

    # Recent scans
    recent_scans = Scan.query.filter(
        Scan.workspace_id.in_(workspace_ids)
    ).order_by(Scan.created_at.desc()).limit(5).all()

    # User's tenants for switcher
    if current_user.is_superadmin:
        user_tenants = Tenant.query.all()
    else:
        user_tenants = current_user.get_tenants()

    return render_template('dashboard/index.html',
                           tenant=tenant,
                           role=role,
                           total_hosts=total_hosts,
                           total_vulns=total_vulns,
                           open_vulns=open_vulns,
                           critical_vulns=critical_vulns,
                           severity_data=severity_data,
                           recent_scans=recent_scans,
                           user_tenants=user_tenants)


@dashboard_bp.route('/vulnerabilities')
@login_required
def vulnerabilities():
    """Vulnerability list with advanced filters."""
    tenant = get_current_tenant()
    if not tenant:
        return render_template('dashboard/no_tenant.html')

    role = get_user_role(tenant.id)
    workspace_ids = [w.id for w in Workspace.query.filter_by(
        tenant_id=tenant.id, is_active=True
    ).all()]

    # Build query with filters
    query = Vulnerability.query.join(Host).filter(
        Host.workspace_id.in_(workspace_ids)
    )

    # --- FILTERS ---
    # Severity
    severity = request.args.get('severity')
    if severity and severity != 'all':
        query = query.filter(Vulnerability.severity == severity)

    # Status
    status = request.args.get('status')
    if status and status != 'all':
        query = query.filter(Vulnerability.status == status)

    # CVE search
    cve = request.args.get('cve', '').strip()
    if cve:
        query = query.filter(Vulnerability.cve_id.ilike(f'%{cve}%'))

    # Host type filter
    host_type = request.args.get('host_type')
    if host_type and host_type != 'all':
        query = query.filter(Host.host_type == host_type)

    # Scanner filter
    scanner = request.args.get('scanner')
    if scanner and scanner != 'all':
        query = query.filter(Vulnerability.scanner == scanner)

    # Date range
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    if date_from:
        try:
            dt_from = datetime.strptime(date_from, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            query = query.filter(Vulnerability.created_at >= dt_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.strptime(date_to, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            dt_to = dt_to + timedelta(days=1)  # include the full day
            query = query.filter(Vulnerability.created_at < dt_to)
        except ValueError:
            pass

    # Text search
    search = request.args.get('q', '').strip()
    if search:
        query = query.filter(
            db.or_(
                Vulnerability.title.ilike(f'%{search}%'),
                Vulnerability.description.ilike(f'%{search}%'),
                Host.ip_address.ilike(f'%{search}%'),
                Host.hostname.ilike(f'%{search}%'),
            )
        )

    # Workspace filter
    workspace_id = request.args.get('workspace_id')
    if workspace_id:
        query = query.filter(Host.workspace_id == int(workspace_id))

    # Sorting
    sort = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'desc')
    sort_map = {
        'severity': Vulnerability.severity,
        'status': Vulnerability.status,
        'created_at': Vulnerability.created_at,
        'cvss': Vulnerability.cvss_score,
        'title': Vulnerability.title,
    }
    sort_col = sort_map.get(sort, Vulnerability.created_at)
    if order == 'asc':
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    # Filter options for sidebar
    workspaces = Workspace.query.filter_by(tenant_id=tenant.id, is_active=True).all()
    scanners = db.session.query(Vulnerability.scanner).distinct().all()

    if current_user.is_superadmin:
        user_tenants = Tenant.query.all()
    else:
        user_tenants = current_user.get_tenants()

    return render_template('dashboard/vulnerabilities.html',
                           tenant=tenant,
                           role=role,
                           pagination=pagination,
                           vulnerabilities=pagination.items,
                           workspaces=workspaces,
                           scanners=[s[0] for s in scanners if s[0]],
                           filters=request.args,
                           user_tenants=user_tenants)


@dashboard_bp.route('/hosts')
@login_required
def hosts():
    """Host inventory list."""
    tenant = get_current_tenant()
    if not tenant:
        return render_template('dashboard/no_tenant.html')

    role = get_user_role(tenant.id)
    workspace_ids = [w.id for w in Workspace.query.filter_by(
        tenant_id=tenant.id, is_active=True
    ).all()]

    query = Host.query.filter(Host.workspace_id.in_(workspace_ids))

    # Filters
    host_type = request.args.get('host_type')
    if host_type and host_type != 'all':
        query = query.filter(Host.host_type == host_type)

    status = request.args.get('status')
    if status and status != 'all':
        query = query.filter(Host.status == status)

    search = request.args.get('q', '').strip()
    if search:
        query = query.filter(
            db.or_(
                Host.ip_address.ilike(f'%{search}%'),
                Host.hostname.ilike(f'%{search}%'),
                Host.os_name.ilike(f'%{search}%'),
            )
        )

    query = query.order_by(Host.last_seen.desc())
    page = request.args.get('page', 1, type=int)
    pagination = query.paginate(page=page, per_page=25, error_out=False)

    if current_user.is_superadmin:
        user_tenants = Tenant.query.all()
    else:
        user_tenants = current_user.get_tenants()

    return render_template('dashboard/hosts.html',
                           tenant=tenant,
                           role=role,
                           pagination=pagination,
                           hosts=pagination.items,
                           filters=request.args,
                           user_tenants=user_tenants)


@dashboard_bp.route('/scans')
@login_required
def scans():
    """Scan history and launcher."""
    tenant = get_current_tenant()
    if not tenant:
        return render_template('dashboard/no_tenant.html')

    role = get_user_role(tenant.id)
    workspace_ids = [w.id for w in Workspace.query.filter_by(
        tenant_id=tenant.id, is_active=True
    ).all()]

    query = Scan.query.filter(Scan.workspace_id.in_(workspace_ids))
    query = query.order_by(Scan.created_at.desc())

    page = request.args.get('page', 1, type=int)
    pagination = query.paginate(page=page, per_page=25, error_out=False)

    workspaces = Workspace.query.filter_by(tenant_id=tenant.id, is_active=True).all()

    if current_user.is_superadmin:
        user_tenants = Tenant.query.all()
    else:
        user_tenants = current_user.get_tenants()

    return render_template('dashboard/scans.html',
                           tenant=tenant,
                           role=role,
                           pagination=pagination,
                           scans=pagination.items,
                           workspaces=workspaces,
                           user_tenants=user_tenants)
