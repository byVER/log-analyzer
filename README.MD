-----

# Traffic Analyzer Go (TAG)

**Traffic Analyzer Go (TAG)** is a high-performance Go tool for monitoring and analyzing incoming web traffic. It is designed to improve security by identifying and detecting various types of cyberattacks and anomalies in real time.

The project works with a data stream that is pre-redirected from your web server (e.g., OpenResty/Nginx) to the **ClickHouse** database, where it is then analyzed.

## Features

1. **Attack Detection:** Identifies and flags potential attacks such as **Cross-Site Scripting (XSS)**, **SQL Injection (SQLi)**, and detects attempts to access **backdoors**. 2. Anomaly Monitoring: Analyzes request patterns to detect suspicious activity, such as vulnerability scanning or DoS-like behavior.
3. User-Agent Analysis: Identifies and analyzes potentially malicious or suspicious User-Agent strings associated with known scanners or tools.
4. High Performance: Written in Go, ensuring high-speed processing and analysis of data extracted from ClickHouse.
5. Centralized Storage: Uses ClickHouse for efficient storage and fast execution of analytical queries across large traffic volumes.

-----

## Future Features

The project is actively developing. Future plans may include:

1. Real-Time Alerts: Integration with alert systems (Slack, Telegram) when critical threats are detected. 2. **IP
   Geolocation:** Adding functionality for determining the geographic location of attacking IP addresses.
2. **Web Interface:** Developing a simple web interface for visualizing monitoring results.

-----

## Project Architecture

The project follows the principles of Clean Architecture (DDD), making it modular and easily testable.

```
├── cmd
│   └── main.go # Application entry point
├── application
│   └── scan_service.go # Business logic coordinating analysis
├── domain
│   ├── analyzer.go # Traffic analysis interface and logic
│   ├── log.go # Log data structures
│   └── repository.go # Data access interface
└── infrastructure
├── clickhouse # Repository implementation for ClickHouse
│   └── repository.go
└── console
└── ui.go # User Interaction (Console)
```

-----

## Installation and Launch

TAG requires: **Go (version 1.25+), ClickHouse**, and a configured web server (e.g., OpenResty/Nginx) for traffic
redirection.

### Step 1: Configuring ClickHouse

First, you need to create a table in your ClickHouse database to receive and store traffic.

Execute the following SQL query (using the `default` database as an example):

```sql
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
) engine = MergeTree PARTITION BY toYYYYMMDD(`@timestamp`)
        ORDER BY (`@timestamp`, remote_addr)
        SETTINGS index_granularity = 8192;
```

### Step 2: Configuring OpenResty/Nginx (Traffic Collection)

To get traffic to ClickHouse, you need to configure your web server to forward logs. The example below uses OpenResty
with the resty.logger.socket library to send JSON data to the Syslog service (vector-service on port 5140), which can
then forward it to ClickHouse.

Example OpenResty configuration (server fragment):

```nginx
# In the http section or at the top level
lua_code_cache on;
lua_need_request_body on;
lua_package_path "/usr/local/openresty/lualib/?.lua;;";
lua_shared_dict log_buffer 10m;

init_worker_by_lua_block {
    local logger = require("resty.logger.socket")
    local ok, err = logger.init({
        host = "vector-service.example.svc.cluster.local", # The address of your log collection service (for example, Vector)
        port = 5140,
        sock_type = "udp",
        flush_limit = 1,
        drop_limit = 100000,
        timeout = 200,
    })
-- ... (logging initialization errors)}

server {
# ... (standard server settings)
    log_by_lua_block {
        local logger = require("resty.logger.socket")
        local cjson = require("cjson.safe")
        
        -- Сбор данных
        local hdr_table = ngx.req.get_headers()
        local hdr_json = cjson.encode(hdr_table) or "{}"
        local log_data = {
            -- ... (fields corresponding to the nginx_visits table)
            event_timestamp = ngx.var.time_iso8601,
            remote_addr = ngx.var.remote_addr,
            -- ... (other fields)
            request_headers_json = hdr_json,
            request_post_data = ngx.var.request_body or ""
        }

        local json_msg = cjson.encode(log_data)
        if not json_msg then return end
        
        -- Formatting in Syslog and sending
        local syslog_msg = "<190>1 " .. ngx.var.time_iso64 .. " nginx nginx - - - " .. json_msg
        local ok_send, err_send = logger.log(syslog_msg)
        
        -- ... (logging sending errors)
    }
    # ... (other location blocks)
}
```

***Note:** Make sure your log collector service (e.g., Vector, Logstash, Fluentd) is properly configured to receive
Syslog messages, parse nested JSON, and load the data into the ClickHouse `default.nginx_visits` table.*

### Step 3: Building and Running TAG

1. **Clone the repository:**

```bash
git clone <YOUR_REPOSITORY_URL>
cd <YOUR_PROJECT_NAME>
```

2. **Build the project:**
   You can use the standard Go build tool to build the executable.

```bash
go build -o analyzer cmd/main.go
```

*The executable file `analyzer` will be created in the root directory.*

**Or use a `Makefile`:**
If you use the provided `Makefile`, the command might look like this:

```bash
make build
# This will likely create the executable file bin/analyzer,
# as shown in your project structure
```

3. **Run:**
   Run the built application, passing the necessary parameters (for example, connection data to ClickHouse).

```bash
./analyzer # or ./bin/analyzer
```

*Add command-line flags to configure the connection to ClickHouse (host, port, user, password) if they are not
configured via environment variables.*

-----

## Usage

```bash
# Run traffic analysis for the last 24 hours with a connection to ClickHouse
./analyzer (flags -start-date 2025-01-01 -batch-size 1000 )
```

-----

## Contributing

We welcome your contributions to this project.

**Developed by VeR Group, open sourced.**

To contribute, please follow these guidelines:

1. Fork the repository and create a new branch for your contribution.
2. Ensure your code complies with Go coding standards.
3. Make a change that addresses a specific issue or adds a suggested improvement.
4. Test your changes thoroughly.
5. Commit your changes, providing a clear and descriptive commit message.
6. Submit your changes to your forked repository.
7. Submit a Pull Request, detailing your changes and providing any relevant information or context.

We appreciate your efforts and will do our best to provide timely feedback.

-----

## License

This project is distributed under the **Open Source License**.

This project is intended for educational purposes and aims to facilitate general cybersecurity assessment. However, we
want to emphasize that **we are not responsible for any malicious use of this application.** It is imperative that users
of this software behave responsibly and ethically. We strongly recommend notifying the entities or individuals involved
before using this software.

-----

## Contacts

Telegran: [@byver](https://t.me/byver)

Email: [vesystem32@gmail.com](mailto:vesystem32@gmail.com)
