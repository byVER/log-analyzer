package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"log-analyzer/domain"
)

type ClickHouseLogRepository struct {
	db *sql.DB
}

func NewClickHouseLogRepository(db *sql.DB) *ClickHouseLogRepository {
	return &ClickHouseLogRepository{db: db}
}

func (r *ClickHouseLogRepository) GetTotalCount(ctx context.Context, startDate string) (int, error) {
	var count int
	query := `SELECT count() FROM default.nginx_visits WHERE toDate("@timestamp") >= ?`
	err := r.db.QueryRowContext(ctx, query, startDate).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to execute count query: %w", err)
	}
	return count, nil
}

func (r *ClickHouseLogRepository) GetLogs(ctx context.Context, offset, limit int, startDate string) ([]*domain.LogEntry, error) {
	query := `
        SELECT
            "@timestamp", remote_addr, request_method, request_uri, status,
            body_bytes_sent, request_time, http_referer, http_user_agent,
            scheme, host, request_headers_json, request_post_data
        FROM default.nginx_visits
        WHERE toDate("@timestamp") >= ?
        ORDER BY "@timestamp"
        LIMIT ? OFFSET ?
    `
	rows, err := r.db.QueryContext(ctx, query, startDate, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query logs: %w", err)
	}
	defer rows.Close()

	var logs []*domain.LogEntry
	for rows.Next() {
		var (
			entry         domain.LogEntry
			requestMethod sql.NullString
			scheme        sql.NullString
		)

		err := rows.Scan(
			&entry.Timestamp, &entry.RemoteAddr, &requestMethod, &entry.RequestURI, &entry.Status,
			&entry.BodyBytesSent, &entry.RequestTime, &entry.HTTPReferer, &entry.HttpUserAgent,
			&scheme, &entry.Host, &entry.RequestHeadersJSON, &entry.RequestPostData,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan log row: %w", err)
		}

		entry.RequestMethod = requestMethod.String
		entry.Scheme = scheme.String

		logs = append(logs, &entry)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating log rows: %w", err)
	}

	return logs, nil
}
