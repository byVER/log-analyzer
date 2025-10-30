package domain

import (
	"context"
)

type LogRepository interface {
	GetTotalCount(ctx context.Context, startDate string) (int, error)
	GetLogs(ctx context.Context, offset, limit int, startDate string) ([]*LogEntry, error)
}
