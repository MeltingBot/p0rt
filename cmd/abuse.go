package cmd

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/p0rt/p0rt/internal/api"
	"github.com/p0rt/p0rt/internal/config"
	"github.com/p0rt/p0rt/internal/security"
)

// abuseCmd represents the abuse command
var abuseCmd = &cobra.Command{
	Use:   "abuse",
	Short: "Manage abuse reports",
	Long: `Manage abuse reports submitted against domains.
	
View pending reports, accept or ban domains based on abuse reports.
Abuse reports are stored in Redis for persistence.`,
	Example: `  # List all pending abuse reports
  p0rt abuse list

  # List all reports (including processed)
  p0rt abuse list --all

  # Ban a domain based on abuse report
  p0rt abuse process report-id-123 ban

  # Accept a domain (dismiss abuse report)
  p0rt abuse process report-id-123 accept

  # Show abuse statistics
  p0rt abuse stats

  # Remote server operations
  p0rt --remote http://localhost:80 abuse list`,
}

var abuseListCmd = &cobra.Command{
	Use:   "list",
	Short: "List abuse reports",
	Long:  `List abuse reports, optionally filtered by status (pending, banned, accepted).
	
By default shows only pending reports. Use --all to see all reports or --status to filter.`,
	Run: func(cmd *cobra.Command, args []string) {
		showAll, _ := cmd.Flags().GetBool("all")
		status, _ := cmd.Flags().GetString("status")
		
		remoteURL, apiKey, _, _, _, useJSON := GetGlobalFlags()
		
		if remoteURL != "" {
			showRemoteAbuseReports(remoteURL, apiKey, status, showAll, useJSON)
		} else {
			showLocalAbuseReports(status, showAll, useJSON)
		}
	},
}

var abuseProcessCmd = &cobra.Command{
	Use:   "process [report-id] [ban|accept]",
	Short: "Process an abuse report",
	Long:  `Process an abuse report by either banning or accepting the domain.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		reportID := args[0]
		action := args[1]
		
		if action != "ban" && action != "accept" {
			fmt.Println("Error: Action must be 'ban' or 'accept'")
			os.Exit(1)
		}
		
		remoteURL, apiKey, _, _, _, useJSON := GetGlobalFlags()
		
		if remoteURL != "" {
			processRemoteAbuseReport(remoteURL, apiKey, reportID, action, useJSON)
		} else {
			processLocalAbuseReport(reportID, action, useJSON)
		}
	},
}

var abuseStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show abuse report statistics",
	Long:  `Display statistics about abuse reports including counts by status.`,
	Run: func(cmd *cobra.Command, args []string) {
		remoteURL, apiKey, _, _, _, useJSON := GetGlobalFlags()
		
		if remoteURL != "" {
			showRemoteAbuseStats(remoteURL, apiKey, useJSON)
		} else {
			showLocalAbuseStats(useJSON)
		}
	},
}

func init() {
	rootCmd.AddCommand(abuseCmd)
	abuseCmd.AddCommand(abuseListCmd)
	abuseCmd.AddCommand(abuseProcessCmd)
	abuseCmd.AddCommand(abuseStatsCmd)
	
	abuseListCmd.Flags().BoolP("all", "a", false, "Show all reports including processed ones")
	abuseListCmd.Flags().StringP("status", "s", "", "Filter by status: pending, banned, accepted")
}

func showLocalAbuseReports(status string, showAll bool, useJSON bool) {
	// Load config to get Redis URL
	cfg, err := config.Load()
	var reportManager *security.AbuseReportManager
	if err == nil && cfg.Storage.RedisURL != "" {
		reportManager = security.NewAbuseReportManagerWithRedis(cfg.Storage.RedisURL)
	} else {
		reportManager = security.NewAbuseReportManager()
	}
	
	if !showAll && status == "" {
		status = "pending"
	}
	
	reports, err := reportManager.ListReports(status)
	if err != nil {
		if useJSON {
			outputError(fmt.Sprintf("Failed to get abuse reports: %v", err))
		} else {
			fmt.Printf("❌ Failed to get abuse reports: %v\n", err)
		}
		return
	}
	
	if useJSON {
		data := map[string]interface{}{
			"reports": reports,
			"count":   len(reports),
			"status":  status,
		}
		outputSuccess(data, "Abuse reports")
		return
	}
	
	if len(reports) == 0 {
		if status == "" {
			fmt.Println("No abuse reports found")
		} else {
			fmt.Printf("No %s abuse reports found\n", status)
		}
		return
	}
	
	fmt.Printf("=== Abuse Reports (%s) ===\n\n", strings.Title(status))
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tDomain\tReporter\tReason\tStatus\tReported\n")
	fmt.Fprintf(w, "--\t------\t--------\t------\t------\t--------\n")
	
	for _, report := range reports {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			report.ID,
			report.Domain,
			report.ReporterIP,
			report.Reason,
			report.Status,
			report.ReportedAt.Format("2006-01-02 15:04"),
		)
	}
	
	w.Flush()
	fmt.Printf("\nTotal: %d reports\n", len(reports))
}

func processLocalAbuseReport(reportID, action string, useJSON bool) {
	// Load config to get Redis URL
	cfg, err := config.Load()
	var reportManager *security.AbuseReportManager
	if err == nil && cfg.Storage.RedisURL != "" {
		reportManager = security.NewAbuseReportManagerWithRedis(cfg.Storage.RedisURL)
	} else {
		reportManager = security.NewAbuseReportManager()
	}
	
	// Get the report first to show details
	report, err := reportManager.GetReport(reportID)
	if err != nil {
		if useJSON {
			outputError(fmt.Sprintf("Report not found: %v", err))
		} else {
			fmt.Printf("❌ Report not found: %v\n", err)
		}
		return
	}
	
	if report.Status != "pending" {
		if useJSON {
			outputError(fmt.Sprintf("Report already processed (status: %s)", report.Status))
		} else {
			fmt.Printf("❌ Report already processed (status: %s)\n", report.Status)
		}
		return
	}
	
	err = reportManager.ProcessReport(reportID, action, "admin")
	if err != nil {
		if useJSON {
			outputError(fmt.Sprintf("Failed to process report: %v", err))
		} else {
			fmt.Printf("❌ Failed to process report: %v\n", err)
		}
		return
	}
	
	if useJSON {
		data := map[string]interface{}{
			"report_id": reportID,
			"action":    action,
			"domain":    report.Domain,
		}
		outputSuccess(data, fmt.Sprintf("Report %s processed", action))
	} else {
		fmt.Printf("✅ Report %s processed: %s\n", reportID, action)
		fmt.Printf("   Domain: %s\n", report.Domain)
		fmt.Printf("   Reason: %s\n", report.Reason)
		
		if action == "ban" {
			fmt.Printf("   🚫 Domain has been banned\n")
		} else {
			fmt.Printf("   ✅ Report dismissed - domain accepted\n")
		}
	}
}

func showLocalAbuseStats(useJSON bool) {
	// Load config to get Redis URL
	cfg, err := config.Load()
	var reportManager *security.AbuseReportManager
	if err == nil && cfg.Storage.RedisURL != "" {
		reportManager = security.NewAbuseReportManagerWithRedis(cfg.Storage.RedisURL)
	} else {
		reportManager = security.NewAbuseReportManager()
	}
	
	stats := reportManager.GetStats()
	
	if useJSON {
		outputSuccess(stats, "Abuse report statistics")
		return
	}
	
	fmt.Println("=== Abuse Report Statistics ===")
	fmt.Printf("Total Reports: %v\n", stats["total_reports"])
	fmt.Printf("Pending: %v\n", stats["pending_reports"])
	fmt.Printf("Banned: %v\n", stats["banned_reports"])
	fmt.Printf("Accepted: %v\n", stats["accepted_reports"])
	fmt.Printf("Redis Available: %v\n", stats["redis_available"])
}

// Remote API functions
func showRemoteAbuseReports(serverURL, apiKey, status string, showAll bool, useJSON bool) {
	client := api.NewClient(serverURL, apiKey)
	
	reports, err := client.GetAbuseReports(status, showAll)
	if err != nil {
		if useJSON {
			outputError(fmt.Sprintf("Failed to get abuse reports: %v", err))
		} else {
			fmt.Printf("❌ Failed to get abuse reports: %v\n", err)
		}
		return
	}
	
	// Convert interface{} to slice of reports
	reportsList, ok := reports.([]interface{})
	if !ok {
		if useJSON {
			outputError("Invalid response format from API")
		} else {
			fmt.Printf("❌ Invalid response format from API\n")
		}
		return
	}
	
	if useJSON {
		data := map[string]interface{}{
			"reports": reportsList,
			"count":   len(reportsList),
			"status":  status,
		}
		outputSuccess(data, "Abuse reports")
		return
	}
	
	if len(reportsList) == 0 {
		if status == "" {
			fmt.Println("No abuse reports found")
		} else {
			fmt.Printf("No %s abuse reports found\n", status)
		}
		return
	}
	
	fmt.Printf("=== Abuse Reports (%s) ===\n\n", strings.Title(status))
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tDomain\tReporter\tReason\tStatus\tReported\n")
	fmt.Fprintf(w, "--\t------\t--------\t------\t------\t--------\n")
	
	for _, item := range reportsList {
		report, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			getString(report, "id"),
			getString(report, "domain"),
			getString(report, "reporter_ip"),
			getString(report, "reason"),
			getString(report, "status"),
			getTimeString(report, "reported_at"),
		)
	}
	
	w.Flush()
	fmt.Printf("\nTotal: %d reports\n", len(reportsList))
}

func processRemoteAbuseReport(serverURL, apiKey, reportID, action string, useJSON bool) {
	client := api.NewClient(serverURL, apiKey)
	
	err := client.ProcessAbuseReport(reportID, action)
	if err != nil {
		if useJSON {
			outputError(fmt.Sprintf("Failed to process report: %v", err))
		} else {
			fmt.Printf("❌ Failed to process report: %v\n", err)
		}
		return
	}
	
	if useJSON {
		data := map[string]interface{}{
			"report_id": reportID,
			"action":    action,
		}
		outputSuccess(data, fmt.Sprintf("Report %s processed", action))
	} else {
		fmt.Printf("✅ Report %s processed: %s\n", reportID, action)
		
		if action == "ban" {
			fmt.Printf("   🚫 Domain has been banned\n")
		} else {
			fmt.Printf("   ✅ Report dismissed - domain accepted\n")
		}
	}
}

func showRemoteAbuseStats(serverURL, apiKey string, useJSON bool) {
	client := api.NewClient(serverURL, apiKey)
	
	stats, err := client.GetAbuseStats()
	if err != nil {
		if useJSON {
			outputError(fmt.Sprintf("Failed to get abuse statistics: %v", err))
		} else {
			fmt.Printf("❌ Failed to get abuse statistics: %v\n", err)
		}
		return
	}
	
	if useJSON {
		outputSuccess(stats, "Abuse report statistics")
		return
	}
	
	statsMap, ok := stats.(map[string]interface{})
	if !ok {
		fmt.Printf("❌ Invalid response format from API\n")
		return
	}
	
	fmt.Println("=== Abuse Report Statistics ===")
	fmt.Printf("Total Reports: %v\n", statsMap["total_reports"])
	fmt.Printf("Pending: %v\n", statsMap["pending_reports"])
	fmt.Printf("Banned: %v\n", statsMap["banned_reports"])
	fmt.Printf("Accepted: %v\n", statsMap["accepted_reports"])
	fmt.Printf("Redis Available: %v\n", statsMap["redis_available"])
}

// Helper functions for parsing API responses
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getTimeString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		// Parse and reformat the time
		if t, err := time.Parse(time.RFC3339, val); err == nil {
			return t.Format("2006-01-02 15:04")
		}
		return val
	}
	return ""
}

