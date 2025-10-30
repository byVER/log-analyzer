package application

import (
	"context"
	"fmt"
	"log"
	"log-analyzer/domain"
	"strings"
)

type ReportData struct {
	IP         string
	ThreatType string
	Count      int
	Evidence   []string
}

type UI interface {
	Init(total int)
	Update(current int, currentItem string)
	RenderReport(report []ReportData, totalIPs int)
	Close()
}

type ScanService struct {
	repo      domain.LogRepository
	ui        UI
	batchSize int
	analyzer  *domain.Analyzer
}

func NewScanService(repo domain.LogRepository, ui UI, batchSize int, analyzer *domain.Analyzer) *ScanService {
	return &ScanService{
		repo:      repo,
		ui:        ui,
		batchSize: batchSize,
		analyzer:  analyzer,
	}
}

func (s *ScanService) Run(ctx context.Context, startDate string) error {
	totalLogs, err := s.repo.GetTotalCount(ctx, startDate)
	if err != nil {
		return fmt.Errorf("failed to get total log count: %w", err)
	}

	if totalLogs == 0 {
		fmt.Println("No logs to analyze. Exiting.")
		return nil
	}

	s.ui.Init(totalLogs)
	defer s.ui.Close()

	ipProfiles := make(map[string][]*domain.LogEntry)
	processedCount := 0
	log.Printf("Total logs to process: %d", totalLogs)
	for offset := 0; offset < totalLogs; offset += s.batchSize {
		logs, err := s.repo.GetLogs(ctx, offset, s.batchSize, startDate)
		if err != nil {
			return fmt.Errorf("failed to get logs batch: %w", err)
		}

		for _, logEntry := range logs {
			processedCount++
			s.ui.Update(processedCount, "")
			ipProfiles[logEntry.RemoteAddr] = append(ipProfiles[logEntry.RemoteAddr], logEntry)
		}
	}

	var reportData []ReportData
	suspiciousIPs := make(map[string]bool)

	for ip, entries := range ipProfiles {
		activities := s.analyzer.Analyze(entries)
		if len(activities) > 0 {
			suspiciousIPs[ip] = true
			for _, activity := range activities {
				var evidenceLines []string
				for _, ev := range activity.Evidence {
					evidenceLines = append(evidenceLines, strings.Replace(ev, "'", "`", -1))
				}

				reportData = append(reportData, ReportData{
					IP:         ip,
					ThreatType: activity.Description,
					Count:      activity.Count,
					Evidence:   evidenceLines,
				})
			}
		}
	}

	s.ui.RenderReport(reportData, len(suspiciousIPs))

	return nil
}
