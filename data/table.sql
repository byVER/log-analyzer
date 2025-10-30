create table default.nginx_visits
(
    `@timestamp`         DateTime64(3),
    remote_addr          String,
    request_method       LowCardinality(String),
    request_uri          String,
    status               UInt16,
    body_bytes_sent      UInt64,
    request_time         Float32,
    http_referer         String,
    http_user_agent      String,
    scheme               LowCardinality(String),
    host                 String,
    request_headers_json String,
    request_post_data    String
)
    engine = MergeTree PARTITION BY toYYYYMMDD(`@timestamp`)
        ORDER BY (`@timestamp`, remote_addr)
        SETTINGS index_granularity = 8192;

