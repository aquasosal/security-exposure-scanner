package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aquasosal/security-exposure-scanner/internal/models"
)

// Scanner handles the scanning logic
type Scanner struct {
	client      *http.Client
	wordlists   map[string][]string
	severityMap map[string]SeverityInfo
	progressCh  chan<- ScanProgress
}

// SeverityInfo contains risk description and remediation for a finding
type SeverityInfo struct {
	Severity    models.Severity
	Risk        string
	Remediation string
}

// ScanProgress represents progress updates during scanning
type ScanProgress struct {
	CurrentFile   string
	CheckedCount  int
	TotalCount    int
	Finding       *models.Finding
	FindingsCount int
}

// NewScanner creates a new scanner instance
func NewScanner(progressCh chan<- ScanProgress) *Scanner {
	return &Scanner{
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		wordlists:   make(map[string][]string),
		severityMap: make(map[string]SeverityInfo),
		progressCh:  progressCh,
	}
}

// LoadWordlists loads wordlists from the config directory
func (s *Scanner) LoadWordlists(configDir string) error {
	wordlistFiles := []string{
		"sensitive-files.txt",
		"config-files.txt",
		"env-files.txt",
		"git-files.txt",
		"cloud-files.txt",
		"docker-files.txt",
		"ci-cd-files.txt",
		"backup-files.txt",
	}

	for _, filename := range wordlistFiles {
		filepath := filepath.Join(configDir, "wordlists", filename)
		entries, err := s.loadWordlist(filepath)
		if err != nil {
			return fmt.Errorf("failed to load wordlist %s: %w", filename, err)
		}
		s.wordlists[filename] = entries
	}

	return nil
}

// LoadSeverityRules loads severity classification rules
func (s *Scanner) LoadSeverityRules(rulesFile string) error {
	// For now, use hardcoded rules
	// In production, load from JSON file
	s.severityMap = map[string]SeverityInfo{
		".git/config": {
			Severity:    models.SeverityCritical,
			Risk:        "Complete repository exposure including history",
			Remediation: "Block .git/ access at server level, verify .git is not deployed",
		},
		".gitignore": {
			Severity:    models.SeverityMedium,
			Risk:        "Repository structure exposed",
			Remediation: "Ensure .gitignore is not deployed to production",
		},
		".env": {
			Severity:    models.SeverityCritical,
			Risk:        "Database credentials, API keys, secrets exposed",
			Remediation: "Rotate all exposed credentials immediately, add .env to .gitignore",
		},
		".env.local": {
			Severity:    models.SeverityCritical,
			Risk:        "Local development secrets exposed",
			Remediation: "Remove from deployment, add to .gitignore and build ignore files",
		},
		".env.production": {
			Severity:    models.SeverityCritical,
			Risk:        "Production secrets exposed",
			Remediation: "Rotate all production credentials immediately",
		},
		".htaccess": {
			Severity:    models.SeverityHigh,
			Risk:        "Directory traversal, authentication bypass",
			Remediation: "Remove .htaccess from production, configure Apache properly",
		},
		"httpd.conf": {
			Severity:    models.SeverityCritical,
			Risk:        "Server configuration, upstream IPs exposed",
			Remediation: "Remove from web-accessible directories, protect with proper permissions",
		},
		"nginx.conf": {
			Severity:    models.SeverityCritical,
			Risk:        "Server configuration, upstream IPs exposed",
			Remediation: "Remove from web-accessible directories, protect with proper permissions",
		},
		"php.ini": {
			Severity:    models.SeverityHigh,
			Risk:        "PHP configuration, file paths exposed",
			Remediation: "Remove from web root, configure PHP properly",
		},
		"web.config": {
			Severity:    models.SeverityCritical,
			Risk:        "IIS configuration, connection strings exposed",
			Remediation: "Remove from web-accessible directories",
		},
		"my.cnf": {
			Severity:    models.SeverityHigh,
			Risk:        "Database credentials, paths exposed",
			Remediation: "Remove from web-accessible directories",
		},
		"pg_hba.conf": {
			Severity:    models.SeverityHigh,
			Risk:        "Authentication rules exposed",
			Remediation: "Remove from web-accessible directories",
		},
		"~/.aws/credentials": {
			Severity:    models.SeverityCritical,
			Risk:        "AWS access keys allowing complete AWS account compromise",
			Remediation: "Revoke exposed keys immediately, enable MFA on AWS account",
		},
		"google-credentials.json": {
			Severity:    models.SeverityCritical,
			Risk:        "GCP service account key exposed",
			Remediation: "Revoke key immediately, create new service account key",
		},
		"docker-compose.yml": {
			Severity:    models.SeverityMedium,
			Risk:        "Service configuration, secrets may be embedded",
			Remediation: "Remove secrets, use environment variables",
		},
		".travis.yml": {
			Severity:    models.SeverityMedium,
			Risk:        "Build configuration may contain secrets hints",
			Remediation: "Review for encrypted secrets, remove sensitive data",
		},
		".github/workflows/*.yml": {
			Severity:    models.SeverityMedium,
			Risk:        "CI/CD configuration may contain API keys",
			Remediation: "Review for secrets, use GitHub Secrets",
		},
		"README.md": {
			Severity:    models.SeverityLow,
			Risk:        "May contain API keys or internal URLs",
			Remediation: "Review for sensitive information, remove secrets",
		},
		".DS_Store": {
			Severity:    models.SeverityMedium,
			Risk:        "macOS file info, may reveal paths",
			Remediation: "Add to .gitignore, remove from production",
		},
		"debug.log": {
			Severity:    models.SeverityMedium,
			Risk:        "Debug information may contain secrets",
			Remediation: "Remove from production, disable debug logging",
		},
	}

	return nil
}

// loadWordlist loads entries from a wordlist file
func (s *Scanner) loadWordlist(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			entries = append(entries, line)
		}
	}

	return entries, scanner.Err()
}

// Scan performs a security scan on the target URL
func (s *Scanner) Scan(ctx context.Context, targetURL string, wordlists []string, concurrent int) ([]models.Finding, error) {
	var findings []models.Finding
	var mu sync.Mutex

	// Collect all files to check
	var filesToCheck []string
	for _, wlName := range wordlists {
		if entries, ok := s.wordlists[wlName]; ok {
			filesToCheck = append(filesToCheck, entries...)
		}
	}

	// Create worker pool
	semaphore := make(chan struct{}, concurrent)
	var wg sync.WaitGroup

	totalFiles := len(filesToCheck)
	checkedCount := 0

	for _, filePath := range filesToCheck {
		wg.Add(1)
		go func(fp string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if finding := s.checkFile(ctx, targetURL, fp); finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()

				s.progressCh <- ScanProgress{
					Finding:       finding,
					FindingsCount: len(findings),
				}
			}

			mu.Lock()
			checkedCount++
			s.progressCh <- ScanProgress{
				CurrentFile:  fp,
				CheckedCount: checkedCount,
				TotalCount:   totalFiles,
			}
			mu.Unlock()
		}(filePath)
	}

	wg.Wait()

	return findings, nil
}

// checkFile checks if a specific file is exposed
func (s *Scanner) checkFile(ctx context.Context, targetURL, filePath string) *models.Finding {
	// Build full URL
	fullURL, err := s.buildURL(targetURL, filePath)
	if err != nil {
		return nil
	}

	// Send HEAD request first (faster)
	req, err := http.NewRequestWithContext(ctx, "HEAD", fullURL, nil)
	if err != nil {
		return nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check if file exists (200 or 403)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
		return nil
	}

	// If 200, do GET request to get content preview
	var contentPreview *string
	var httpStatus *int
	if resp.StatusCode == http.StatusOK {
		httpStatus = &resp.StatusCode

		getResp, err := s.client.Get(fullURL)
		if err == nil {
			defer getResp.Body.Close()

			// Read first 500 bytes for preview
			buf := make([]byte, 500)
			n, _ := getResp.Body.Read(buf)
			if n > 0 {
				preview := string(buf[:n])
				// Sanitize preview
				contentPreview = &preview
			}
		}
	}

	// Get severity info
	severityInfo := s.getSeverityInfo(filePath)

	// Extract file type
	fileType := s.getFileType(filePath)

	return &models.Finding{
		FilePath:        filePath,
		FileType:        fileType,
		Severity:        severityInfo.Severity,
		URL:             fullURL,
		HTTPStatus:      httpStatus,
		ContentPreview:  contentPreview,
		RiskDescription: &severityInfo.Risk,
		Remediation:     &severityInfo.Remediation,
		Confirmed:       resp.StatusCode == http.StatusOK,
	}
}

// buildURL constructs a full URL from base and path
func (s *Scanner) buildURL(baseURL, filePath string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Join base URL path with file path
	base.Path = filepath.Join(base.Path, filePath)

	return base.String(), nil
}

// getSeverityInfo returns severity information for a file
func (s *Scanner) getSeverityInfo(filePath string) SeverityInfo {
	// Check exact match first
	if info, ok := s.severityMap[filePath]; ok {
		return info
	}

	// Check pattern match (wildcards)
	for pattern, info := range s.severityMap {
		if strings.Contains(pattern, "*") {
			// Simple wildcard matching
			pattern := strings.ReplaceAll(pattern, "*", "")
			if strings.Contains(filePath, pattern) {
				return info
			}
		}
	}

	// Default severity
	return SeverityInfo{
		Severity:    models.SeverityMedium,
		Risk:        "Sensitive configuration file exposed",
		Remediation: "Remove from production, verify deployment pipeline",
	}
}

// getFileType determines the type of exposed file
func (s *Scanner) getFileType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch {
	case ext == ".env" || strings.Contains(filePath, ".env"):
		return "environment-file"
	case strings.Contains(filePath, ".git"):
		return "git-file"
	case strings.Contains(filePath, "nginx") || strings.Contains(filePath, "apache") || strings.Contains(filePath, "httpd"):
		return "webserver-config"
	case strings.Contains(filePath, "docker"):
		return "docker-config"
	case strings.Contains(filePath, ".yml") || strings.Contains(filePath, ".yaml"):
		return "yaml-config"
	case ext == ".conf":
		return "config-file"
	case strings.Contains(filePath, ".aws") || strings.Contains(filePath, "credentials"):
		return "cloud-credentials"
	case strings.Contains(filePath, "backup") || strings.Contains(filePath, ".bak"):
		return "backup-file"
	case ext == ".log":
		return "log-file"
	default:
		return "unknown"
	}
}
