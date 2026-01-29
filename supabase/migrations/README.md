# Database migrations for Security Exposure Scanner

## Migration 001: Create targets table

```sql
CREATE TABLE targets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  url TEXT NOT NULL,
  target_type VARCHAR(50) DEFAULT 'web',
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  user_id VARCHAR(255)
);

CREATE INDEX idx_targets_active ON targets(is_active);
CREATE INDEX idx_targets_type ON targets(target_type);
```

## Migration 002: Create scans table

```sql
CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
  status VARCHAR(50) DEFAULT 'pending',
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  total_files_checked INTEGER DEFAULT 0,
  total_findings INTEGER DEFAULT 0,
  findings_by_severity JSONB DEFAULT '{}',
  scan_config JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scans_target ON scans(target_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
```

## Migration 003: Create findings table

```sql
CREATE TABLE findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  file_path TEXT NOT NULL,
  file_type VARCHAR(100) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  status VARCHAR(20) DEFAULT 'open',
  url TEXT NOT NULL,
  http_status INTEGER,
  content_preview TEXT,
  risk_description TEXT,
  remediation TEXT,
  confirmed BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_type ON findings(file_type);
```

## Migration 004: Create schedules table

```sql
CREATE TABLE schedules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  schedule_type VARCHAR(50) NOT NULL,
  cron_expression TEXT,
  is_active BOOLEAN DEFAULT true,
  last_run_at TIMESTAMPTZ,
  next_run_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_schedules_target ON schedules(target_id);
CREATE INDEX idx_schedules_active ON schedules(is_active);
```

## Migration 005: Create indexes for performance

```sql
-- Composite indexes for common queries
CREATE INDEX idx_scans_target_status ON scans(target_id, status);
CREATE INDEX idx_findings_scan_severity ON findings(scan_id, severity);
```

## Setup instructions

Run these migrations in Supabase SQL editor:

1. Enable UUID extension (if not already enabled)
```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

2. Run migrations in order: 001, 002, 003, 004, 005

3. Enable Row Level Security (optional)
```sql
ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE schedules ENABLE ROW LEVEL SECURITY;
```
