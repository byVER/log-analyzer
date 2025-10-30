package domain

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type SuspiciousActivity struct {
	Description string
	Count       int
	Evidence    []string
	Hits        map[string]SignatureHit
}

type Analyzer struct {
	toolSignatures     []string
	sqliSignatures     []string
	xssSignatures      []string
	backDoorSignatures []string
}
type SignatureHit struct {
	Signature string
	Count     int
	Source    string
}

var hexRegex = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

func unhexEscape(s string) string {
	return hexRegex.ReplaceAllStringFunc(s, func(match string) string {
		hexVal, err := strconv.ParseUint(match[2:], 16, 8)
		if err != nil {
			return match
		}
		return string(rune(hexVal))
	})
}
func extractJSONValues(data interface{}) []string {
	var values []string
	switch v := data.(type) {
	case string:
		values = append(values, v)
	case map[string]interface{}:
		for _, subVal := range v {
			values = append(values, extractJSONValues(subVal)...)
		}
	case []interface{}:
		for _, item := range v {
			values = append(values, extractJSONValues(item)...)
		}
	}
	return values
}

func handleSignatureHit(signature string, source string, hits map[string]SignatureHit) {
	if hit, exists := hits[signature]; exists {
		hit.Count++
		hits[signature] = hit
	} else {
		hits[signature] = SignatureHit{
			Signature: signature,
			Count:     1,
			Source:    source,
		}
	}
}

func parsePostData(postData string, headersJSON string) string {
	var headers map[string]string
	var contentType string
	if err := json.Unmarshal([]byte(headersJSON), &headers); err == nil {
		contentType = strings.ToLower(headers["content-type"])
	}

	var valuesToAnalyze []string
	if strings.Contains(contentType, "application/json") {
		var jsonData interface{}
		if err := json.Unmarshal([]byte(postData), &jsonData); err == nil {
			valuesToAnalyze = extractJSONValues(jsonData)
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		parsedData, err := url.ParseQuery(postData)
		if err == nil {
			for _, values := range parsedData {
				valuesToAnalyze = append(valuesToAnalyze, values...)
			}
		}
	}

	if len(valuesToAnalyze) == 0 {
		return postData
	}
	return strings.Join(valuesToAnalyze, " ")
}

func NewAnalyzer(toolSigs, sqliSigs, xssSigs, backDoorSigs []string) *Analyzer {
	return &Analyzer{
		toolSignatures:     toolSigs,
		sqliSignatures:     sqliSigs,
		xssSignatures:      xssSigs,
		backDoorSignatures: backDoorSigs,
	}
}
func (a *Analyzer) Analyze(logs []*LogEntry) []SuspiciousActivity {
	var activities []SuspiciousActivity

	if activity, found := a.analyzeRapidRequests(logs, 10*time.Second, 20); found {
		activities = append(activities, activity)
	}
	toolHits := make(map[string]SignatureHit)
	sqliHits := make(map[string]SignatureHit)
	xssHits := make(map[string]SignatureHit)
	backDoorHits := make(map[string]SignatureHit)

	for _, log := range logs {
		ua := strings.ToLower(log.HttpUserAgent)
		for _, toolSig := range a.toolSignatures {
			if strings.Contains(ua, toolSig) {
				handleSignatureHit(toolSig, ua, toolHits)
			}
		}

		parsedURL, err := url.Parse(log.RequestURI)
		if err != nil {
			parsedURL = &url.URL{Path: log.RequestURI}
		}

		var queryValuesBuilder strings.Builder
		for _, values := range parsedURL.Query() {
			for _, value := range values {
				queryValuesBuilder.WriteString(value)
				queryValuesBuilder.WriteString(" ")
			}
		}

		pathPart, _ := url.QueryUnescape(parsedURL.Path)
		pathPart = unhexEscape(pathPart)

		queryValuesPart, _ := url.QueryUnescape(queryValuesBuilder.String())
		queryValuesPart = unhexEscape(queryValuesPart)

		postDataContent := parsePostData(log.RequestPostData, log.RequestHeadersJSON)
		postDataPart, _ := url.QueryUnescape(postDataContent)
		postDataPart = unhexEscape(postDataPart)
		pathPart = strings.ToLower(pathPart)
		pathPart = strings.ReplaceAll(pathPart, "/", "")
		checkStr := strings.ToLower(pathPart + " " + queryValuesPart + " " + postDataPart)
		for _, sqliSig := range a.sqliSignatures {
			sqliSig := unhexEscape(sqliSig)
			if strings.Contains(checkStr, sqliSig) {
				handleSignatureHit(sqliSig, checkStr, sqliHits)
			}
		}

		for _, xssSig := range a.xssSignatures {
			xssSig := unhexEscape(xssSig)
			if strings.Contains(checkStr, xssSig) {
				handleSignatureHit(xssSig, checkStr, xssHits)
			}
		}
		for _, backDoorSig := range a.backDoorSignatures {
			backDoorSig := unhexEscape(backDoorSig)
			if strings.Contains(checkStr, backDoorSig) {
				handleSignatureHit(backDoorSig, checkStr, backDoorHits)
			}
		}
	}

	if len(toolHits) > 0 {
		activities = append(activities, SuspiciousActivity{
			Description: "Usage of automated scanning tool(s) detected",
			Count:       sumMapValues(toolHits),
			Evidence:    formatEvidence(toolHits),
			Hits:        toolHits,
		})
	}
	if len(sqliHits) > 0 {
		activities = append(activities, SuspiciousActivity{
			Description: "Potential SQL Injection attempt(s) detected",
			Count:       sumMapValues(sqliHits),
			Evidence:    formatEvidence(sqliHits),
			Hits:        sqliHits,
		})
	}
	if len(xssHits) > 0 {
		activities = append(activities, SuspiciousActivity{
			Description: "Potential XSS attempt(s) detected",
			Count:       sumMapValues(xssHits),
			Evidence:    formatEvidence(xssHits),
			Hits:        xssHits,
		})
	}
	if len(backDoorHits) > 0 {
		activities = append(activities, SuspiciousActivity{
			Description: "Potential backDoor attempt(s) detected",
			Count:       sumMapValues(backDoorHits),
			Evidence:    formatEvidence(backDoorHits),
			Hits:        backDoorHits,
		})
	}

	return activities
}

func (a *Analyzer) analyzeRapidRequests(logs []*LogEntry, window time.Duration, threshold int) (SuspiciousActivity, bool) {
	if len(logs) < threshold {
		return SuspiciousActivity{}, false
	}
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].Timestamp.Before(logs[j].Timestamp)
	})
	maxCount := 0
	for i := 0; i <= len(logs)-threshold; i++ {
		if logs[i+threshold-1].Timestamp.Sub(logs[i].Timestamp) <= window {
			currentCount := 0
			for j := i; j < len(logs); j++ {
				if logs[j].Timestamp.Sub(logs[i].Timestamp) <= window {
					currentCount++
				} else {
					break
				}
			}
			if currentCount > maxCount {
				maxCount = currentCount
			}
		}
	}
	if maxCount >= threshold {
		return SuspiciousActivity{
			Description: "Multiple requests in a small time rate",
			Count:       maxCount,
		}, true
	}
	return SuspiciousActivity{}, false
}
func sumMapValues(m map[string]SignatureHit) int {
	sum := 0
	for _, item := range m {
		sum += item.Count
	}
	return sum
}
func formatEvidence(m map[string]SignatureHit) []string {
	var evidence []string
	limit := 5
	for _, val := range m {
		if limit == 0 {
			break
		}
		evidence = append(evidence, fmt.Sprintf("'%s'  (%d times)", val.Signature, val.Count))
		limit--
	}
	return evidence
}
