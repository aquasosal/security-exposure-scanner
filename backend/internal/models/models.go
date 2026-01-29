package models

import (
	"time"

	"github.com/google/uuid"
)

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Status types for scans
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
)

// Status types for findings
type FindingStatus string

const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusAcknowledged  FindingStatus = "acknowledged"
	FindingStatusFixed         FindingStatus = "fixed"
	FindingStatusFalsePositive FindingStatus = "false_positive"
)

// Target represents a URL or service to scan
type Target struct {
	ID         uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name       string    `json:"name" gorm:"type:varchar(255);not null"`
	URL        string    `json:"url" gorm:"type:text;not null"`
	TargetType string    `json:"target_type" gorm:"type:varchar(50);default:'web'"`
	IsActive   bool      `json:"is_active" gorm:"default:true"`
	CreatedAt  time.Time `json:"created_at" gorm:"default:now()"`
	UpdatedAt  time.Time `json:"updated_at" gorm:"default:now()"`
	UserID     *string   `json:"user_id,omitempty" gorm:"type:varchar(255)"`
}

// Scan represents a scanning session
type Scan struct {
	ID                 uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TargetID           uuid.UUID  `json:"target_id" gorm:"type:uuid;not null"`
	Status             ScanStatus `json:"status" gorm:"type:varchar(50);default:'pending'"`
	StartedAt          *time.Time `json:"started_at" gorm:"type:timestamptz"`
	CompletedAt        *time.Time `json:"completed_at" gorm:"type:timestamptz"`
	TotalFilesChecked  int        `json:"total_files_checked" gorm:"default:0"`
	TotalFindings      int        `json:"total_findings" gorm:"default:0"`
	FindingsBySeverity JSONMap    `json:"findings_by_severity" gorm:"type:jsonb;default:'{}'"`
	ScanConfig         JSONMap    `json:"scan_config" gorm:"type:jsonb;default:'{}'"`
	CreatedAt          time.Time  `json:"created_at" gorm:"default:now()"`
}

// Finding represents a discovered exposed file
type Finding struct {
	ID              uuid.UUID     `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ScanID          uuid.UUID     `json:"scan_id" gorm:"type:uuid;not null"`
	FilePath        string        `json:"file_path" gorm:"type:text;not null"`
	FileType        string        `json:"file_type" gorm:"type:varchar(100);not null"`
	Severity        Severity      `json:"severity" gorm:"type:varchar(20);not null"`
	Status          FindingStatus `json:"status" gorm:"type:varchar(20);default:'open'"`
	URL             string        `json:"url" gorm:"type:text;not null"`
	HTTPStatus      *int          `json:"http_status" gorm:"type:integer"`
	ContentPreview  *string       `json:"content_preview" gorm:"type:text"`
	RiskDescription *string       `json:"risk_description" gorm:"type:text"`
	Remediation     *string       `json:"remediation" gorm:"type:text"`
	Confirmed       bool          `json:"confirmed" gorm:"default:false"`
	CreatedAt       time.Time     `json:"created_at" gorm:"default:now()"`
}

// Schedule represents scheduled scans
type Schedule struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TargetID       uuid.UUID  `json:"target_id" gorm:"type:uuid;not null"`
	Name           string     `json:"name" gorm:"type:varchar(255);not null"`
	ScheduleType   string     `json:"schedule_type" gorm:"type:varchar(50);not null"`
	CronExpression *string    `json:"cron_expression" gorm:"type:text"`
	IsActive       bool       `json:"is_active" gorm:"default:true"`
	LastRunAt      *time.Time `json:"last_run_at" gorm:"type:timestamptz"`
	NextRunAt      *time.Time `json:"next_run_at" gorm:"type:timestamptz"`
	CreatedAt      time.Time  `json:"created_at" gorm:"default:now()"`
}

// JSONMap is a custom type for storing JSONB data
type JSONMap map[string]interface{}

// ScanConfig represents configuration for a scan
type ScanConfig struct {
	Depth      int      `json:"depth"`
	Wordlists  []string `json:"wordlists"`
	Timeout    int      `json:"timeout"`
	Concurrent int      `json:"concurrent"`
}
