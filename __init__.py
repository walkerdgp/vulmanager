"""
VulnManager Database Models
Multi-tenant vulnerability management with RBAC
"""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin

db = SQLAlchemy()
bcrypt = Bcrypt()


# ============================================================
# MULTI-TENANCY & AUTH
# ============================================================

class Tenant(db.Model):
    """Top-level organization (client/company) for multi-tenant isolation."""
    __tablename__ = 'tenants'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    slug = db.Column(db.String(100), nullable=False, unique=True, index=True)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    workspaces = db.relationship('Workspace', backref='tenant', lazy='dynamic')
    users = db.relationship('TenantUser', backref='tenant', lazy='dynamic')

    def __repr__(self):
        return f'<Tenant {self.name}>'


class User(UserMixin, db.Model):
    """User account with local or LDAP authentication."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True, index=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password_hash = db.Column(db.String(256))  # null for LDAP-only users
    display_name = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    is_superadmin = db.Column(db.Boolean, default=False)  # platform-wide admin
    auth_source = db.Column(db.String(20), default='local')  # 'local' or 'ldap'
    ldap_dn = db.Column(db.String(500))  # LDAP distinguished name
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    tenant_roles = db.relationship('TenantUser', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        if not self.password_hash:
            return False
        return bcrypt.check_password_hash(self.password_hash, password)

    def get_role_for_tenant(self, tenant_id):
        tu = TenantUser.query.filter_by(user_id=self.id, tenant_id=tenant_id).first()
        return tu.role if tu else None

    def get_tenants(self):
        return [tu.tenant for tu in self.tenant_roles.all()]

    def __repr__(self):
        return f'<User {self.username}>'


class TenantUser(db.Model):
    """Maps users to tenants with specific roles (RBAC)."""
    __tablename__ = 'tenant_users'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')
    # Roles: 'admin', 'analyst', 'viewer'
    #   admin   = full CRUD + manage users in tenant
    #   analyst = create/edit vulns, run scans
    #   viewer  = read-only access

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('user_id', 'tenant_id', name='uq_user_tenant'),
    )


# ============================================================
# CORE VULNERABILITY DATA
# ============================================================

class Workspace(db.Model):
    """A workspace groups related scans/vulns (e.g., per project, network segment)."""
    __tablename__ = 'workspaces'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    hosts = db.relationship('Host', backref='workspace', lazy='dynamic',
                            cascade='all, delete-orphan')
    scans = db.relationship('Scan', backref='workspace', lazy='dynamic',
                            cascade='all, delete-orphan')

    __table_args__ = (
        db.UniqueConstraint('tenant_id', 'name', name='uq_tenant_workspace'),
    )

    def __repr__(self):
        return f'<Workspace {self.name}>'


class Host(db.Model):
    """An asset/host discovered or scanned."""
    __tablename__ = 'hosts'

    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspaces.id'), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)  # supports IPv6
    hostname = db.Column(db.String(255))
    mac_address = db.Column(db.String(17))
    os_name = db.Column(db.String(200))
    os_version = db.Column(db.String(100))
    host_type = db.Column(db.String(50), default='server')
    # host_type: 'server', 'workstation', 'network_device', 'iot', 'cloud', 'container', 'other'
    status = db.Column(db.String(20), default='active')  # 'active', 'inactive', 'decommissioned'
    owner = db.Column(db.String(200))
    location = db.Column(db.String(200))
    notes = db.Column(db.Text)
    tags = db.Column(db.JSON, default=list)  # flexible tagging
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='host', lazy='dynamic',
                                      cascade='all, delete-orphan')
    services = db.relationship('Service', backref='host', lazy='dynamic',
                               cascade='all, delete-orphan')

    __table_args__ = (
        db.UniqueConstraint('workspace_id', 'ip_address', name='uq_workspace_host_ip'),
        db.Index('idx_host_type', 'host_type'),
    )

    @property
    def vuln_count(self):
        return self.vulnerabilities.count()

    @property
    def critical_count(self):
        return self.vulnerabilities.filter_by(severity='critical').count()

    def __repr__(self):
        return f'<Host {self.ip_address}>'


class Service(db.Model):
    """Network services running on a host."""
    __tablename__ = 'services'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False, index=True)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default='tcp')  # tcp, udp
    service_name = db.Column(db.String(100))
    version = db.Column(db.String(200))
    banner = db.Column(db.Text)
    status = db.Column(db.String(20), default='open')  # open, closed, filtered
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('host_id', 'port', 'protocol', name='uq_host_service'),
    )


class Vulnerability(db.Model):
    """A vulnerability finding linked to a host."""
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), index=True)

    # Identification
    title = db.Column(db.String(500), nullable=False)
    cve_id = db.Column(db.String(20), index=True)  # e.g., CVE-2023-5550
    cwe_id = db.Column(db.String(20))  # e.g., CWE-79
    external_id = db.Column(db.String(100))  # scanner-specific ID

    # Classification
    severity = db.Column(db.String(20), nullable=False, default='info', index=True)
    # severity: 'critical', 'high', 'medium', 'low', 'info'
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(200))

    # Details
    description = db.Column(db.Text)
    solution = db.Column(db.Text)
    references = db.Column(db.JSON, default=list)  # list of URLs
    evidence = db.Column(db.Text)  # proof/output from scanner
    affected_component = db.Column(db.String(300))  # e.g., "Apache 2.4.29"

    # Workflow
    status = db.Column(db.String(20), default='open', index=True)
    # status: 'open', 'confirmed', 'in_progress', 'resolved', 'false_positive', 'accepted_risk'
    assigned_to = db.Column(db.String(200))
    due_date = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)

    # Source
    scanner = db.Column(db.String(50))  # 'nmap', 'openvas', 'nessus', 'zap', 'burp', 'manual'
    tool_output = db.Column(db.Text)  # raw output from tool

    # Metadata
    tags = db.Column(db.JSON, default=list)
    custom_fields = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index('idx_vuln_severity_status', 'severity', 'status'),
        db.Index('idx_vuln_created', 'created_at'),
        db.Index('idx_vuln_cve', 'cve_id'),
    )

    def __repr__(self):
        return f'<Vulnerability {self.cve_id or self.title[:40]}>'


class VulnerabilityHistory(db.Model):
    """Audit trail for vulnerability state changes."""
    __tablename__ = 'vulnerability_history'

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=False)
    changed_by = db.Column(db.String(80))
    field_name = db.Column(db.String(50))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    change_note = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


# ============================================================
# SCANNING
# ============================================================

class Scan(db.Model):
    """A scan execution record."""
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspaces.id'), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    scanner = db.Column(db.String(50), nullable=False)  # tool used
    scan_type = db.Column(db.String(50))  # 'full', 'quick', 'web_app', 'custom'
    target = db.Column(db.Text)  # IPs, ranges, URLs
    status = db.Column(db.String(20), default='pending')
    # status: 'pending', 'running', 'completed', 'failed', 'cancelled'
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    host_count = db.Column(db.Integer, default=0)
    vuln_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    raw_output = db.Column(db.Text)  # stored scan output
    launched_by = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic')

    def __repr__(self):
        return f'<Scan {self.name} ({self.scanner})>'


# ============================================================
# INTEGRATIONS & WEBHOOKS
# ============================================================

class Webhook(db.Model):
    """Outbound webhook configuration."""
    __tablename__ = 'webhooks'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    secret = db.Column(db.String(200))  # for HMAC signature
    events = db.Column(db.JSON, default=list)
    # events: ['vuln.created', 'vuln.resolved', 'scan.completed', 'host.created']
    is_active = db.Column(db.Boolean, default=True)
    last_triggered = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class ApiKey(db.Model):
    """API keys for external integrations."""
    __tablename__ = 'api_keys'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    key_hash = db.Column(db.String(256), nullable=False, unique=True)
    prefix = db.Column(db.String(10), nullable=False)  # first chars shown to user
    is_active = db.Column(db.Boolean, default=True)
    last_used = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
