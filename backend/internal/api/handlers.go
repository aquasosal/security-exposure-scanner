package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/aquasosal/security-exposure-scanner/internal/models"
	"github.com/aquasosal/security-exposure-scanner/internal/scanner"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Handlers manages API endpoints
type Handlers struct {
	scanner *scanner.Scanner
}

// NewHandlers creates new API handlers
func NewHandlers(scan *scanner.Scanner) *Handlers {
	return &Handlers{
		scanner: scan,
	}
}

// CreateScanRequest represents request to create a new scan
type CreateScanRequest struct {
	TargetURL  string            `json:"target_url" binding:"required"`
	ScanConfig models.ScanConfig `json:"scan_config"`
}

// CreateScan creates a new scan
func (h *Handlers) CreateScan(c *gin.Context) {
	var req CreateScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scanID := uuid.New()

	// In a real implementation, save to database here
	// For now, just return the scan ID

	c.JSON(http.StatusCreated, gin.H{
		"scan_id": scanID,
		"status":  models.ScanStatusPending,
	})
}

// GetScanStatus returns scan status
func (h *Handlers) GetScanStatus(c *gin.Context) {
	scanID := c.Param("scan_id")
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan_id is required"})
		return
	}

	// In a real implementation, fetch from database
	// For now, return mock data
	c.JSON(http.StatusOK, gin.H{
		"scan_id":             scanID,
		"status":              models.ScanStatusCompleted,
		"progress":            100,
		"total_files_checked": 500,
		"total_findings":      12,
		"findings_by_severity": gin.H{
			"critical": 2,
			"high":     3,
			"medium":   5,
			"low":      2,
		},
	})
}

// GetScanResults returns scan results
func (h *Handlers) GetScanResults(c *gin.Context) {
	scanID := c.Param("scan_id")
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan_id is required"})
		return
	}

	severity := c.Query("severity")

	// In a real implementation, fetch from database with filtering
	// For now, return mock data
	findings := []models.Finding{
		{
			FilePath:        ".git/config",
			FileType:        "git-file",
			Severity:        models.SeverityCritical,
			Status:          models.FindingStatusOpen,
			URL:             "https://example.com/.git/config",
			RiskDescription: strPtr("Complete repository exposure including history"),
			Remediation:     strPtr("Block .git/ access at server level"),
			Confirmed:       true,
		},
	}

	if severity != "" {
		filtered := []models.Finding{}
		for _, f := range findings {
			if string(f.Severity) == severity {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":        scanID,
		"total_findings": len(findings),
		"findings":       findings,
	})
}

// CreateTarget creates a new target
func (h *Handlers) CreateTarget(c *gin.Context) {
	var target models.Target
	if err := c.ShouldBindJSON(&target); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// In a real implementation, save to database
	// For now, just return the target with ID
	target.ID = uuid.New()
	target.CreatedAt = time.Now()
	target.UpdatedAt = time.Now()

	c.JSON(http.StatusCreated, target)
}

// ListTargets returns all targets
func (h *Handlers) ListTargets(c *gin.Context) {
	// In a real implementation, fetch from database
	// For now, return empty list
	c.JSON(http.StatusOK, gin.H{
		"targets": []models.Target{},
	})
}

// ExecuteScan executes a scan immediately
func (h *Handlers) ExecuteScan(c *gin.Context) {
	var req CreateScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create progress channel
	progressCh := make(chan scanner.ScanProgress, 100)

	// Start scanning in goroutine
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		// Use default wordlists if none specified
		wordlists := req.ScanConfig.Wordlists
		if len(wordlists) == 0 {
			wordlists = []string{"sensitive-files.txt", "config-files.txt"}
		}

		findings, err := h.scanner.Scan(ctx, req.TargetURL, wordlists, req.ScanConfig.Concurrent)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"target_url":     req.TargetURL,
			"total_findings": len(findings),
			"findings":       findings,
		})
	}()

	// Return immediately, actual results will be saved to database
	c.JSON(http.StatusAccepted, gin.H{
		"message": "Scan started",
	})
}

// StreamProgress streams scan progress via SSE
func (h *Handlers) StreamProgress(c *gin.Context) {
	scanID := c.Param("scan_id")

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Streaming not supported"})
		return
	}

	// In a real implementation, subscribe to progress channel
	// For now, send mock progress events
	sendEvent := func(eventType string, data interface{}) {
		jsonData, _ := json.Marshal(data)
		c.Writer.WriteString("event: " + eventType + "\n")
		c.Writer.WriteString("data: " + string(jsonData) + "\n\n")
		flusher.Flush()
	}

	sendEvent("scan.started", gin.H{"scan_id": scanID})

	// Mock progress updates
	for i := 0; i <= 100; i += 20 {
		time.Sleep(500 * time.Millisecond)
		sendEvent("scan.progress", gin.H{
			"scan_id":       scanID,
			"progress":      i,
			"checked_count": i * 5,
			"total_count":   500,
		})
	}

	sendEvent("scan.completed", gin.H{
		"scan_id":        scanID,
		"total_findings": 12,
		"findings_count": 12,
	})
}

// Helper function
func strPtr(s string) *string {
	return &s
}
