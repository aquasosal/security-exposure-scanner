#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCAN_BIN="$PROJECT_ROOT/backend/bin/scan"

usage() {
    echo "🛡️  Security Exposure Scanner CLI"
    echo ""
    echo "Usage: ./scan.sh [OPTIONS] --url <TARGET_URL>"
    echo ""
    echo "Options:"
    echo "  --url <url>              Target URL to scan (required)"
    echo "  --category <cats>         Categories to check (comma-separated)"
    echo "                           Available: env, git, config, sensitive, cloud, docker, ci-cd, backup, status"
    echo "  --severity <levels>        Severity levels to show (comma-separated)"
    echo "                           Available: critical, high, medium, low"
    echo "  --output <file>          Save results to JSON file"
    echo "  --verbose                Show content preview for each finding"
    echo "  --concurrent <num>       Number of concurrent requests (default: 10)"
    echo "  --timeout <seconds>       Request timeout (default: 30)"
    echo "  --help                   Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./scan.sh --url https://example.com"
    echo "  ./scan.sh --url https://example.com --category env,git,status"
    echo "  ./scan.sh --url https://example.com --severity critical,high"
    echo "  ./scan.sh --url https://example.com --output results.json --verbose"
    echo ""
}

CATEGORY=""
SEVERITY=""
OUTPUT=""
VERBOSE=""
CONCURRENT="10"
TIMEOUT="30"
TARGET_URL=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --url)
            TARGET_URL="$2"
            shift 2
            ;;
        --category)
            CATEGORY="$2"
            shift 2
            ;;
        --severity)
            SEVERITY="$2"
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE="--verbose=true"
            shift
            ;;
        --concurrent)
            CONCURRENT="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ -z "$TARGET_URL" ]]; then
    echo "Error: --url is required"
    echo ""
    usage
    exit 1
fi

if [[ ! -f "$SCAN_BIN" ]]; then
    echo "Building scan binary..."
    cd "$PROJECT_ROOT/backend"
    go build -o bin/scan ./cmd/scan
fi

"$SCAN_BIN" \
    --url "$TARGET_URL" \
    ${CATEGORY:+--category "$CATEGORY"} \
    ${SEVERITY:+--severity "$SEVERITY"} \
    ${OUTPUT:+--output "$OUTPUT"} \
    ${VERBOSE:+--verbose} \
    --concurrent "$CONCURRENT" \
    --timeout "$TIMEOUT"
