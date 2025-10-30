package domain

import (
	"time"
)

type LogEntry struct {
	Timestamp          time.Time `db:"@timestamp"`
	RemoteAddr         string    `db:"remote_addr"`
	RequestMethod      string    `db:"request_method"`
	RequestURI         string    `db:"request_uri"`
	Status             uint16    `db:"status"`
	BodyBytesSent      uint64    `db:"body_bytes_sent"`
	RequestTime        float32   `db:"request_time"`
	HTTPReferer        string    `db:"http_referer"`
	HttpUserAgent      string    `db:"http_user_agent"`
	Scheme             string    `db:"scheme"`
	Host               string    `db:"host"`
	RequestHeadersJSON string    `db:"request_headers_json"`
	RequestPostData    string    `db:"request_post_data"`
}
