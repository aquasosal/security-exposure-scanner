package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aquasosal/security-exposure-scanner/internal/models"
	"github.com/aquasosal/security-exposure-scanner/internal/scanner"
)

func main() {
	targetURL := flag.String("url", "", "Target URL to scan (required)")
	categories := flag.String("category", "", "Comma-separated categories (env,git,config,sensitive,cloud,docker,ci-cd,backup,status)")
	severityFilter := flag.String("severity", "", "Comma-separated severity levels to show (critical,high,medium,low)")
	outputFile := flag.String("output", "", "Output file path (JSON format)")
	verbose := flag.Bool("verbose", false, "Show content preview for each finding")
	concurrent := flag.Int("concurrent", 10, "Number of concurrent requests")
	timeout := flag.Int("timeout", 30, "Request timeout in seconds")

	flag.Parse()

	if *targetURL == "" {
		fmt.Println("Error: --url is required")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("🛡️  Security Exposure Scanner CLI")
	fmt.Println("🎯 Target:", *targetURL)
	fmt.Println()

	progressCh := make(chan scanner.ScanProgress, 100)
	scan := scanner.NewScanner(progressCh)

	configDir := "./backend/config"
	if err := scan.LoadWordlists(configDir); err != nil {
		fmt.Printf("Warning: Failed to load wordlists: %v\n", err)
		fmt.Println("Continuing with default wordlists...\n")
	}

	if err := scan.LoadSeverityRules(""); err != nil {
		fmt.Printf("Error: Failed to load severity rules: %v\n", err)
		os.Exit(1)
	}

	wordlists := getWordlists(*categories)
	if len(wordlists) == 0 {
		wordlists = []string{"sensitive-files.txt", "config-files.txt", "env-files.txt", "git-files.txt"}
	}

	fmt.Printf("📂 Scanning with %d wordlist(s): %s\n", len(wordlists), strings.Join(wordlists, ", "))
	fmt.Printf("⚡ Concurrent requests: %d\n", *concurrent)
	fmt.Printf("⏱️  Timeout: %ds\n", *timeout)
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	fmt.Println("🔍 Starting scan...")
	fmt.Println()

	findings, err := scan.Scan(ctx, *targetURL, wordlists, *concurrent)
	if err != nil {
		fmt.Printf("❌ Scan error: %v\n", err)
		os.Exit(1)
	}

	filteredFindings := filterFindings(findings, *severityFilter)

	displayResults(filteredFindings, *verbose)

	if *outputFile != "" {
		if err := saveResults(filteredFindings, *outputFile); err != nil {
			fmt.Printf("❌ Failed to save results: %v\n", err)
		} else {
			fmt.Printf("\n💾 Results saved to: %s\n", *outputFile)
		}
	}

	fmt.Println()
	summary(filteredFindings)
}

func getWordlists(categories string) []string {
	if categories == "" {
		return nil
	}

	categoryMap := map[string]string{
		"env":         "env-files.txt",
		"environment": "env-files.txt",
		"git":         "git-files.txt",
		"config":      "config-files.txt",
		"webserver":   "config-files.txt",
		"sensitive":   "sensitive-files.txt",
		"database":    "sensitive-files.txt",
		"cloud":       "cloud-files.txt",
		"credentials": "cloud-files.txt",
		"docker":      "docker-files.txt",
		"container":   "docker-files.txt",
		"ci-cd":       "ci-cd-files.txt",
		"cicd":        "ci-cd-files.txt",
		"backup":      "backup-files.txt",
		"status":      "status-debug-pages.txt",
		"debug":       "status-debug-pages.txt",
	}

	selected := strings.Split(categories, ",")
	wordlists := []string{}

	for _, cat := range selected {
		cat = strings.TrimSpace(strings.ToLower(cat))
		if wl, ok := categoryMap[cat]; ok {
			wordlists = append(wordlists, wl)
		} else {
			fmt.Printf("⚠️  Unknown category: %s\n", cat)
		}
	}

	return unique(wordlists)
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	for _, entry := range slice {
		if !keys[entry] {
			keys[entry] = true
			list = append(list, entry)
		}
	}

	return list
}

func filterFindings(findings []models.Finding, severityFilter string) []models.Finding {
	if severityFilter == "" {
		return findings
	}

	filtered := strings.Split(severityFilter, ",")
	result := []models.Finding{}

	for _, f := range findings {
		for _, sev := range filtered {
			if strings.EqualFold(string(f.Severity), strings.TrimSpace(sev)) {
				result = append(result, f)
				break
			}
		}
	}

	return result
}

func displayResults(findings []models.Finding, verbose bool) {
	if len(findings) == 0 {
		fmt.Println("✅ No exposures found!")
		return
	}

	fmt.Printf("🚨 Found %d exposure(s):\n\n", len(findings))

	for i, f := range findings {
		severityIcon := getSeverityIcon(f.Severity)
		fmt.Printf("%s [%d] %s\n", severityIcon, i+1, f.FilePath)
		fmt.Printf("    URL: %s\n", f.URL)
		fmt.Printf("    Type: %s\n", f.FileType)
		fmt.Printf("    Severity: %s\n", f.Severity)
		if f.HTTPStatus != nil {
			fmt.Printf("    HTTP Status: %d\n", *f.HTTPStatus)
		}
		if verbose && f.ContentPreview != nil && len(*f.ContentPreview) > 0 {
			preview := *f.ContentPreview
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			fmt.Printf("    Preview: %s\n", preview)
		}
		if f.RiskDescription != nil {
			fmt.Printf("    Risk: %s\n", *f.RiskDescription)
		}
		if f.Remediation != nil {
			fmt.Printf("    Remediation: %s\n", *f.Remediation)
		}
		fmt.Println()
	}
}

func getSeverityIcon(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical:
		return "🔴 CRITICAL"
	case models.SeverityHigh:
		return "🟠 HIGH"
	case models.SeverityMedium:
		return "🟡 MEDIUM"
	case models.SeverityLow:
		return "🔵 LOW"
	default:
		return "⚪ INFO"
	}
}

func summary(findings []models.Finding) {
	fmt.Println("📊 Summary:")
	fmt.Println(strings.Repeat("─", 50))

	counts := map[models.Severity]int{
		models.SeverityCritical: 0,
		models.SeverityHigh:     0,
		models.SeverityMedium:   0,
		models.SeverityLow:      0,
	}

	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Printf("  🔴 Critical: %d\n", counts[models.SeverityCritical])
	fmt.Printf("  🟠 High: %d\n", counts[models.SeverityHigh])
	fmt.Printf("  🟡 Medium: %d\n", counts[models.SeverityMedium])
	fmt.Printf("  🔵 Low: %d\n", counts[models.SeverityLow])
	fmt.Printf("  ─────────\n")
	fmt.Printf("  Total: %d\n", len(findings))
}

func saveResults(findings []models.Finding, filepath string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath, data, 0644)
}

func repeat(s string, count int) string {
	return strings.Repeat(s, count)
}
