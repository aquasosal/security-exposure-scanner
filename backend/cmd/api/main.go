package main

import (
	"log"

	"github.com/aquasosal/security-exposure-scanner/internal/api"
	"github.com/aquasosal/security-exposure-scanner/internal/scanner"
	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize scanner
	scan := scanner.NewScanner(nil)

	// Load wordlists (in production, use absolute path)
	// For now, skip loading in Lambda context
	// scan.LoadWordlists("./config")

	// Load severity rules
	scan.LoadSeverityRules("")

	// Initialize handlers
	handlers := api.NewHandlers(scan)

	// Setup Gin router
	r := gin.Default()

	// API v1 routes
	v1 := r.Group("/api/v1")
	{
		// Scan routes
		scans := v1.Group("/scans")
		{
			scans.POST("", handlers.CreateScan)
			scans.GET("/:scan_id/status", handlers.GetScanStatus)
			scans.GET("/:scan_id/results", handlers.GetScanResults)
			scans.POST("/execute", handlers.ExecuteScan)
			scans.GET("/:scan_id/stream", handlers.StreamProgress)
		}

		// Target routes
		targets := v1.Group("/targets")
		{
			targets.POST("", handlers.CreateTarget)
			targets.GET("", handlers.ListTargets)
		}
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Start server
	port := "8080"
	log.Printf("Server starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
