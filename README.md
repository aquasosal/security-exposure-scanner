# Security Exposure Scanner

Automated security scanner for detecting exposed development and configuration files in web applications.

## Features

- **500+ Sensitive File Detection**: Scans for exposed .git, .env, config files, backups, and more
- **Real-time Scanning**: Live progress updates via Server-Sent Events (SSE)
- **Severity Classification**: Critical, High, Medium, Low, Info severity levels
- **Remediation Guidance**: Each finding includes risk description and fix steps
- **Multi-Target Support**: Scan multiple URLs, schedule automated scans
- **Modern UI**: Next.js frontend with TypeScript and Tailwind CSS
- **CLI Tool**: Command-line interface for quick scanning without UI

## Architecture

```
Frontend (Next.js) → Vercel
     ↓
API Gateway (optional)
     ↓
Backend (Go) → AWS Lambda
     ↓
Supabase (PostgreSQL)
```

## Tech Stack

- **Backend**: Go 1.25.6, Gin framework
- **Frontend**: Next.js 16.x, TypeScript, Tailwind CSS
- **Database**: Supabase (PostgreSQL)
- **Deployment**: AWS Lambda (backend), Vercel (frontend)

## Quick Start

### CLI Tool (Recommended for Quick Scans)

```bash
# Basic scan
./scan.sh --url https://example.com

# Scan specific categories
./scan.sh --url https://example.com --category env,git,status

# Filter by severity
./scan.sh --url https://example.com --severity critical,high

# Save results to JSON
./scan.sh --url https://example.com --output results.json

# Verbose mode with content preview
./scan.sh --url https://example.com --verbose

# All options
./scan.sh --url https://example.com --category env,git --severity critical,high --output results.json --verbose --concurrent 20
```

**Available Categories:**
- `env` - Environment files (.env, .env.local, etc.)
- `git` - Git metadata (.git/config, .gitignore, etc.)
- `config` - Server configs (nginx.conf, apache.conf, .htaccess, etc.)
- `sensitive` - Database/app configs (my.cnf, php.ini, settings.py, etc.)
- `cloud` - Cloud credentials (aws credentials, google credentials, etc.)
- `docker` - Docker files (Dockerfile, docker-compose.yml)
- `ci-cd` - CI/CD configs (.travis.yml, .github/workflows, etc.)
- `backup` - Backup files (*.bak, backup.sql, etc.)
- `status` - Status/debug pages (server-status, phpinfo, actuator, etc.)

**Available Severity Levels:**
- `critical` - Immediate action required
- `high` - Review and remediate soon
- `medium` - Review when possible
- `low` - Low risk, consider for cleanup

### Quick Start (Test Mode)

### Backend Server

```bash
cd backend

# Run local server (no database required for basic testing)
go run cmd/api/main.go
```

Server runs on http://localhost:8080

### Frontend Server

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

Open http://localhost:3000

### Testing the Scanner

1. Start backend: `cd backend && go run cmd/api/main.go`
2. Start frontend: `cd frontend && npm run dev`
3. Open http://localhost:3000
4. Enter a URL (e.g., `https://example.com`)
5. Click "🔍 스캔 시작" (Start Scan)
6. View real-time results

**Note**: In test mode, the scanner will return mock results. Connect to Supabase for full functionality.

## Database Setup

1. Create a new project in Supabase
2. Run the migrations in `supabase/migrations/README.md`
3. Update `.env` with Supabase credentials

## Environment Variables

```env
# Supabase
SUPABASE_URL=your-supabase-url
SUPABASE_KEY=your-supabase-anon-key

# AWS (for Lambda deployment)
AWS_REGION=ap-northeast-2
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
```

## Deployment

### Backend (AWS Lambda)

```bash
cd backend/scripts

# Build for Lambda
./build-lambda.sh

# Deploy to Lambda
./deploy-lambda.sh
```

### Frontend (Vercel)

```bash
cd frontend

# Install Vercel CLI
npm i -g vercel

# Deploy
vercel
```

**Vercel Configuration:**
1. Import from GitHub: `aquasosal/security-exposure-scanner`
2. Set Root Directory: `frontend`
3. Set Environment Variables:
   - `NEXT_PUBLIC_API_URL`: Your Lambda URL (e.g., `https://abc123.execute-api.ap-northeast-2.amazonaws.com`)
4. Deploy!

**Note**: If testing locally without backend, frontend will return mock results for demonstration purposes.

## API Endpoints

### Scans
- `POST /api/v1/scans` - Create new scan
- `GET /api/v1/scans/:id/status` - Get scan status
- `GET /api/v1/scans/:id/results` - Get scan results
- `POST /api/v1/scans/execute` - Execute immediate scan
- `GET /api/v1/scans/:id/stream` - SSE stream for live progress

### Targets
- `POST /api/v1/targets` - Create target
- `GET /api/v1/targets` - List all targets

## Scanned File Types

- **Git files**: .git/config, .gitignore, .gitattributes
- **Environment files**: .env, .env.local, .env.production
- **Server configs**: nginx.conf, httpd.conf, .htaccess, php.ini
- **Cloud credentials**: ~/.aws/credentials, google-credentials.json
- **Database configs**: my.cnf, pg_hba.conf, mongod.conf
- **Docker files**: Dockerfile, docker-compose.yml
- **CI/CD files**: .travis.yml, .github/workflows/*.yml
- **Backup files**: *.bak, *.backup, *.old, backup.zip
- **Development files**: README.md, .DS_Store, debug.log

## Repository

https://github.com/aquasosal/security-exposure-scanner
