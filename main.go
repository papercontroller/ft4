package main

import (
	"fmt"
	"sort"
	"strings"
)

type IncidentEvent struct {
	Time        string
	RawEvent    string
	Source      string
	Severity    string
	AttackStage string
	Risk        string
}

type ThreatRisk struct {
	ThreatName string
	Likelihood int
	Impact     int
	Score      int
	Category   string
	Priority   int
}

type AnomalyMetric struct {
	MetricName    string
	NormalScore   float64
	ObservedScore float64
	Delta         float64
	IsAnomaly     bool
}

type RecoveryStep struct {
	StepID      int
	Action      string
	Component   string
	TargetTimeM int
}

func main() {
	events := []IncidentEvent{
		{"09:01", "15 failed logins", "10.20.4.15", "Medium", "credential attack", "Medium"},
		{"09:03", "21 failed logins", "10.20.4.15", "High", "credential attack", "High"},
		{"09:04", "Successful login", "10.20.4.15", "High", "privilege compromise", "High"},
		{"09:07", "320 files modified", "10.20.4.15", "Critical", "data destruction", "Critical"},
		{"09:08", "CPU usage increased to 95%", "Research-Server-01", "High", "data destruction", "High"},
		{"09:10", "1,200 files encrypted", "Research-Server-01", "Critical", "data destruction", "Critical"},
		{"09:12", "Backup deletion attempt", "Research-Server-01", "Critical", "recovery attack", "Critical"},
		{"09:13", "Outbound connection to unknown IP", "Research-Server-01", "High", "exfiltration", "High"},
		{"09:15", "Database access spike", "Research-Server-01", "High", "exfiltration", "High"},
		{"09:18", "Antivirus disabled", "Research-Server-01", "Critical", "persistence", "Critical"},
	}

	fmt.Println("PART A: INCIDENT ANALYSIS")
	fmt.Printf("%-6s | %-34s | %-20s | %-12s\n", "Time", "Event", "Attack Stage", "Risk")
	fmt.Println(strings.Repeat("-", 80))
	for _, e := range events {
		fmt.Printf("%-6s | %-34s | %-20s | %-12s\n", e.Time, e.RawEvent, e.AttackStage, e.Risk)
	}

	rawThreats := []ThreatRisk{
		{ThreatName: "Ransomware", Likelihood: 4, Impact: 5, Priority: 1},
		{ThreatName: "Backup destruction", Likelihood: 3, Impact: 5, Priority: 2},
		{ThreatName: "Credential compromise", Likelihood: 4, Impact: 4, Priority: 3},
		{ThreatName: "Data exfiltration", Likelihood: 3, Impact: 4, Priority: 4},
		{ThreatName: "Privilege escalation", Likelihood: 3, Impact: 4, Priority: 5},
	}

	var assessedThreats []ThreatRisk
	for _, t := range rawThreats {
		score := t.Likelihood * t.Impact
		category := ""
		switch {
		case score >= 17:
			category = "Critical (17-25)"
		case score >= 10:
			category = "High (10-16)"
		case score >= 5:
			category = "Medium (5-9)"
		default:
			category = "Low (1-4)"
		}
		t.Score = score
		t.Category = category
		assessedThreats = append(assessedThreats, t)
	}

	sort.Slice(assessedThreats, func(i, j int) bool {
		return assessedThreats[i].Priority < assessedThreats[j].Priority
	})

	fmt.Println("\nPART B: RISK MATRIX")
	fmt.Printf("%-24s | %-10s | %-8s | %-6s | %-16s | %-8s\n",
		"Threat", "Likelihood", "Impact", "Score", "Risk Level", "Priority")
	fmt.Println(strings.Repeat("-", 86))
	for _, t := range assessedThreats {
		fmt.Printf("%-24s | %-10d | %-8d | %-6d | %-16s | Priority %d\n",
			t.ThreatName, t.Likelihood, t.Impact, t.Score, t.Category, t.Priority)
	}

	steps := []RecoveryStep{
		{1, "Detect incident", "SIEM/EDR (Wazuh) & NIDS (Suricata)", 2},
		{2, "Isolate affected system", "Managed Switch VLAN Quarantine", 3},
		{3, "Preserve evidence", "Hypervisor Live RAM & Disk Dump", 5},
		{4, "Activate backup", "Immutable WORM Storage Controller", 5},
		{5, "Restore services", "Recovery Environment (Clean VM Spin-up)", 8},
		{6, "Verify integrity", "Automated Hash & Malware Scanner", 4},
		{7, "Return to production", "Core Router & Ingress Gateway Cutover", 3},
	}

	cumulativeTime := 0
	fmt.Println("\nPART D: RECOVERY PLAN")
	fmt.Printf("%-4s | %-28s | %-38s | %-12s | %-12s\n", "Step", "Action", "Component", "Duration", "Elapsed")
	fmt.Println(strings.Repeat("-", 102))
	for _, s := range steps {
		cumulativeTime += s.TargetTimeM
		fmt.Printf("%-4d | %-28s | %-38s | %2d min     | T+%2d min\n",
			s.StepID, s.Action, s.Component, s.TargetTimeM, cumulativeTime)
	}
	fmt.Println(strings.Repeat("-", 102))
	fmt.Printf("Total RTO: %d minutes\nConfigured RPO: 3 minutes\n", cumulativeTime)

	threshold := 0.75
	metrics := []AnomalyMetric{
		{MetricName: "Login failures", NormalScore: 0.10, ObservedScore: 0.81},
		{MetricName: "File modifications", NormalScore: 0.12, ObservedScore: 0.96},
		{MetricName: "CPU usage", NormalScore: 0.20, ObservedScore: 0.88},
		{MetricName: "Outbound traffic", NormalScore: 0.15, ObservedScore: 0.79},
		{MetricName: "Database requests", NormalScore: 0.18, ObservedScore: 0.91},
	}

	anomaliesCount := 0
	var highestAnomaly AnomalyMetric

	fmt.Println("\nPART E: AI ANOMALY DETECTION")
	fmt.Printf("%-20s | %-12s | %-14s | %-10s | %-14s\n",
		"Metric", "Normal Score", "Observed Score", "Delta", "Anomaly Flag")
	fmt.Println(strings.Repeat("-", 80))

	for i := range metrics {
		m := &metrics[i]
		m.Delta = m.ObservedScore - m.NormalScore
		if m.ObservedScore >= threshold {
			m.IsAnomaly = true
			anomaliesCount++
		}
		if m.ObservedScore > highestAnomaly.ObservedScore {
			highestAnomaly = *m
		}

		flag := "NORMAL"
		if m.IsAnomaly {
			flag = fmt.Sprintf("ANOMALY (>=%.2f)", threshold)
		}
		fmt.Printf("%-20s | %-12.2f | %-14.2f | +%-9.2f | %-14s\n",
			m.MetricName, m.NormalScore, m.ObservedScore, m.Delta, flag)
	}

	detectionRate := (float64(anomaliesCount) / float64(len(metrics))) * 100.0
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("Total Metrics: %d\n", len(metrics))
	fmt.Printf("Detected Anomalies: %d\n", anomaliesCount)
	fmt.Printf("Detection Rate: %.1f%%\n", detectionRate)
	fmt.Printf("Highest Priority Event: %s (Observed: %.2f, Delta: +%.2f)\n",
		highestAnomaly.MetricName, highestAnomaly.ObservedScore, highestAnomaly.Delta)
}