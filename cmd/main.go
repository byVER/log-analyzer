package main

import (
    "bufio"
    "context"
    "database/sql"
    "flag"
    "fmt"
    "log"
    "os"
    "strings"
    "time"

    "log-analyzer/application"
    "log-analyzer/domain"
    "log-analyzer/infrastructure/clickhouse"
    "log-analyzer/infrastructure/console"

    _ "github.com/ClickHouse/clickhouse-go/v2"
    "github.com/joho/godotenv"
)

func loadSignaturesFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, fmt.Errorf("could not open signature file %s: %w", filePath, err)
    }
    defer file.Close()

    var signatures []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" && !strings.HasPrefix(line, "#") {
            signatures = append(signatures, strings.ToLower(line))
        }
    }

    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("error reading signature file %s: %w", filePath, err)
    }

    log.Printf("Loaded %d signatures from %s", len(signatures), filePath)
    return signatures, nil
}

func main() {
    if err := godotenv.Load(); err != nil {
        log.Println("Warning: .env file not found, using default or environment variables")
    }

    chHost := getEnv("CH_HOST", "localhost")
    chPort := getEnv("CH_PORT", "9000")
    chDatabase := getEnv("CH_DATABASE", "default")
    chUser := getEnv("CH_USER", "default")
    chPassword := getEnv("CH_PASSWORD", "")

    dsn := fmt.Sprintf("clickhouse://%s:%s@%s:%s/%s", chUser, chPassword, chHost, chPort, chDatabase)

    today := time.Now().Format("2006-01-02")

    startDate := flag.String("start-date", today, "Start date for log scanning (YYYY-MM-DD)")
    batchSize := flag.Int("batch-size", 5000, "Number of records to process in one batch")
    flag.Parse()

    toolSigs, err := loadSignaturesFromFile("data/Listoftools.dat")
    if err != nil {
        log.Fatal(err)
    }
    sqliSigs, err := loadSignaturesFromFile("data/SQLpyloads.dat")
    if err != nil {
        log.Fatal(err)
    }
    xssSigs, err := loadSignaturesFromFile("data/XSSpyloads.dat")
    if err != nil {
        log.Fatal(err)
    }
    backDoorSigs, err := loadSignaturesFromFile("data/Backdoor.dat")
    if err != nil {
        log.Fatal(err)
    }

    conn, err := connectToClickHouse(dsn + "?dial_timeout=5s")
    if err != nil {
        log.Fatalf("Could not connect to ClickHouse: %v", err)
    }
    defer conn.Close()

    ctx := context.Background()
    if err := conn.PingContext(ctx); err != nil {
        log.Fatalf("Could not ping ClickHouse: %v", err)
    }

    logRepo := clickhouse.NewClickHouseLogRepository(conn)
    consoleUI := console.NewConsoleUI()

    analyzer := domain.NewAnalyzer(toolSigs, sqliSigs, xssSigs, backDoorSigs)
    scanService := application.NewScanService(logRepo, consoleUI, *batchSize, analyzer)

    log.Printf("Starting log analysis from date: %s", *startDate)
    // Передаем значение флага в сервис
    if err := scanService.Run(ctx, *startDate); err != nil {
        log.Fatalf("An error occurred during scan: %v", err)
    }

    fmt.Println("\nScan finished successfully.")
}

func getEnv(key, fallback string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return fallback
}

func connectToClickHouse(dsn string) (*sql.DB, error) {
    db, err := sql.Open("clickhouse", dsn)
    if err != nil {
        return nil, err
    }
    return db, nil
}
