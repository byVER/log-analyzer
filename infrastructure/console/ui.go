package console

import (
	"fmt"
	"log-analyzer/application"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/schollz/progressbar/v3"
)

type ConsoleUI struct {
	bar *progressbar.ProgressBar
}

func NewConsoleUI() *ConsoleUI {
	return &ConsoleUI{}
}

func (c *ConsoleUI) Init(total int) {
	c.bar = progressbar.NewOptions(
		total,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionSetDescription("[1/2 SCANNING LOGS]"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
}

func (c *ConsoleUI) Update(current int, currentItem string) {
	if c.bar != nil {
		c.bar.Set(current)
	}
}

func (c *ConsoleUI) RenderReport(report []application.ReportData, totalIPs int) {
	if len(report) == 0 {
		fmt.Println("\n[2/2 ANALYSIS COMPLETE] No suspicious activities detected.")
		return
	}

	fmt.Println("\n[2/2 ANALYSIS COMPLETE] Suspicious activities found:")

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	t.AppendHeader(table.Row{"IP Address", "Threat Type", "Count", "Evidence Examples"})

	lastIP := ""
	for _, data := range report {
		ipDisplay := data.IP
		if ipDisplay == lastIP {
			ipDisplay = ""
		}

		t.AppendRow(table.Row{
			ipDisplay,
			data.ThreatType,
			data.Count,
			data.Evidence,
		})

		lastIP = data.IP
	}

	t.SetStyle(table.StyleLight)
	t.Style().Options.SeparateRows = true
	t.Render()
	fmt.Printf("\nTotal suspicious IPs detected: %d\n", totalIPs)
}

func (c *ConsoleUI) Close() {
	if c.bar != nil {
		c.bar.Finish()
	}
}
