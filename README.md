# Security Exposure Scanner

Automated security scanner for detecting exposed development and configuration files in web applications.

## Features

- **500+ Sensitive File Detection**: Scans for exposed .git, .env, config files, backups, and more
- **Real-time Scanning**: Live progress updates via Server-Sent Events (SSE)
- **Severity Classification**: Critical, High, Medium, Low, Info severity levels
- **Remediation Guidance**: Each finding includes risk description and fix steps
- **Multi-Target Support**: Scan multiple URLs, schedule automated scans
- **Modern UI**: Next.js frontend with TypeScript and Tailwind CSS

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

### Prerequisites

- Go 1.25.6+
- Node.js 18+
- Supabase account
- AWS account (for Lambda deployment)

### Backend Setup

```bash
cd backend

# Install dependencies
go mod download

# Run local server
go run cmd/api/main.go
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

Open http://localhost:3000

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

## License

MIT

## Repository

https://github.com/aquasosal/security-exposure-scanner
