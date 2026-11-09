-- Database Schema for TrustVault
-- Compatible with SQLite3 and MySQL

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL -- 'ADMIN', 'OWNER', 'VIEWER'
);

CREATE TABLE IF NOT EXISTS documents (
    id VARCHAR(50) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL,
    mime_type VARCHAR(50) NOT NULL,
    size_bytes INTEGER NOT NULL,
    encrypted_content TEXT NOT NULL,
    owner_id VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id VARCHAR(50) NOT NULL,
    user_id VARCHAR(50) NOT NULL,
    level VARCHAR(20) NOT NULL, -- 'READ', 'EDIT'
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    granted_by VARCHAR(50) NOT NULL,
    UNIQUE(doc_id, user_id),
    FOREIGN KEY (doc_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    actor_id VARCHAR(50) NOT NULL,
    actor_email VARCHAR(120) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_id VARCHAR(50) NOT NULL,
    details TEXT NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'SUCCESS', 'DENIED'
    previous_hash VARCHAR(64) NOT NULL,
    hash VARCHAR(64) NOT NULL,
    FOREIGN KEY (actor_id) REFERENCES users(id)
);

-- Seed initial accounts with default password: 'Password@123'
-- Werkzeug pbkdf2:sha256 hash representation
INSERT OR IGNORE INTO users (id, name, email, password_hash, role) VALUES
('usr_admin', 'Alice Administrator', 'admin@trustvault.internal', 'scrypt:32768:8:1$uHkmWc3dD5qA9Mlh$f1a7d6e4695b774640bb8e6981881729b71fc41ae4bf26b8e3adcb630db7ee49a3dd06aa081fa2417765103c80ff65b6f3807a977e20ca94a5c531405e3ecfa9', 'ADMIN'),
('usr_owner_1', 'Bob Finance Lead', 'bob@trustvault.internal', 'scrypt:32768:8:1$uHkmWc3dD5qA9Mlh$f1a7d6e4695b774640bb8e6981881729b71fc41ae4bf26b8e3adcb630db7ee49a3dd06aa081fa2417765103c80ff65b6f3807a977e20ca94a5c531405e3ecfa9', 'OWNER'),
('usr_owner_2', 'Carol Legal Counsel', 'carol@trustvault.internal', 'scrypt:32768:8:1$uHkmWc3dD5qA9Mlh$f1a7d6e4695b774640bb8e6981881729b71fc41ae4bf26b8e3adcb630db7ee49a3dd06aa081fa2417765103c80ff65b6f3807a977e20ca94a5c531405e3ecfa9', 'OWNER'),
('usr_viewer_1', 'David External Auditor', 'david@auditfirm.com', 'scrypt:32768:8:1$uHkmWc3dD5qA9Mlh$f1a7d6e4695b774640bb8e6981881729b71fc41ae4bf26b8e3adcb630db7ee49a3dd06aa081fa2417765103c80ff65b6f3807a977e20ca94a5c531405e3ecfa9', 'VIEWER'),
('usr_viewer_2', 'Eve Suspicious User', 'eve@untrusted.org', 'scrypt:32768:8:1$uHkmWc3dD5qA9Mlh$f1a7d6e4695b774640bb8e6981881729b71fc41ae4bf26b8e3adcb630db7ee49a3dd06aa081fa2417765103c80ff65b6f3807a977e20ca94a5c531405e3ecfa9', 'VIEWER');

-- Seed initial documents
INSERT OR IGNORE INTO documents (id, title, category, mime_type, size_bytes, encrypted_content, owner_id) VALUES
('doc_payroll_2026', 'Executive_Compensation_Q3_2026.pdf', 'Finance', 'application/pdf', 245000, 'ENC_GCM_AES256[BaseSalary:StrictConfidential,ExecutiveBonuses:Level4ApprovalRequired]', 'usr_owner_1'),
('doc_merger_term_sheet', 'Project_Titan_Acquisition_NDA.pdf', 'Legal', 'application/pdf', 182000, 'ENC_GCM_AES256[TargetEntity:AcmeHoldings,Valuation:Confidential,Jurisdiction:Delaware]', 'usr_owner_2');

-- Seed initial permissions
INSERT OR IGNORE INTO permissions (doc_id, user_id, level, granted_by) VALUES
('doc_payroll_2026', 'usr_owner_1', 'EDIT', 'SYSTEM'),
('doc_payroll_2026', 'usr_viewer_1', 'READ', 'usr_owner_1'),
('doc_merger_term_sheet', 'usr_owner_2', 'EDIT', 'SYSTEM');

-- Seed genesis audit logs
INSERT OR IGNORE INTO audit_logs (id, timestamp, actor_id, actor_email, action, resource_id, details, status, previous_hash, hash) VALUES
(1, '2026-11-01 09:12:00', 'usr_owner_1', 'bob@trustvault.internal', 'DOC_UPLOAD', 'doc_payroll_2026', 'Uploaded Executive_Compensation_Q3_2026.pdf', 'SUCCESS', '0000000000000000000000000000000000000000000000000000000000000000', '3f5c71a92e104b90e4fbc87123aa12d990471b05819e917d848123bcdefa1023'),
(2, '2026-11-02 10:00:00', 'usr_owner_1', 'bob@trustvault.internal', 'PERMISSION_GRANT', 'doc_payroll_2026', 'Granted READ access to david@auditfirm.com', 'SUCCESS', '3f5c71a92e104b90e4fbc87123aa12d990471b05819e917d848123bcdefa1023', '892a7fe91b2c55d143c98afbb1024e09842a8b9812984ea0bcdaf912837bcda1');