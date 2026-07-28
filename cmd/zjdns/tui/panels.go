package tui

import (
	"fmt"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
)

func renderDashboard(m *Model) string {
	logPanel := renderLogPanel(m)
	statsPanel := renderStatsPanel(m)
	content := lipgloss.JoinHorizontal(lipgloss.Top, logPanel, statsPanel)
	return lipgloss.JoinVertical(lipgloss.Left,
		renderTitleBar(m),
		content,
		renderFooter(m),
	)
}

func renderTitleBar(m *Model) string {
	title := styleTitle.Render("ZJDNS Dashboard")
	help := styleHelp.Render("[Q]uit  [F]ilter  [R]efresh")
	gap := lipgloss.NewStyle().Width(max(0, m.width-lipgloss.Width(title)-lipgloss.Width(help))).Render("")
	return lipgloss.JoinHorizontal(lipgloss.Center, title, gap, help)
}

func renderFooter(m *Model) string {
	uptime := "just now"
	if m.uptime > 0 {
		dur := m.uptime
		switch {
		case dur < 60:
			uptime = fmt.Sprintf("%ds", uint64(dur))
		case dur < 3600:
			uptime = fmt.Sprintf("%dm%ds", uint64(dur)/60, uint64(dur)%60)
		default:
			uptime = fmt.Sprintf("%dh%dm", uint64(dur)/3600, (uint64(dur)%3600)/60)
		}
	}
	left := styleFooter.Render(fmt.Sprintf("Uptime: %s │ QPS: %d │ Cache: %d entries",
		uptime, m.currentQPS, m.stats.Entries))
	mode := "live"
	if m.paused {
		mode = "paused"
	}
	right := styleFooter.Render(fmt.Sprintf("Mode: %s │ OK", mode))
	gap := lipgloss.NewStyle().Width(max(0, m.width-lipgloss.Width(left)-lipgloss.Width(right))).Render("")
	return lipgloss.JoinHorizontal(lipgloss.Center, left, gap, right)
}

// ── Query log panel ──────────────────────────────────────────────────────────

func renderLogPanel(m *Model) string {
	logWidth := max(m.width/2, 30)

	var lines []string
	filterHint := ""
	if m.filterMode {
		filterHint = fmt.Sprintf(" [filter: %s_]", m.filter)
	}

	for _, e := range m.filteredLog() {
		badge := resultBadge(e.Result)
		latency := fmt.Sprintf("%.1fms", e.ResponseTime)
		line := fmt.Sprintf("%s %6s  %-5s %s",
			badge, latency, e.Qtype, e.Qname)
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		lines = append(lines, styleHelp.Render("Waiting for queries..."))
	}

	content := strings.Join(lines, "\n")

	m.logVP.SetContent(content)
	m.logVP.GotoBottom()

	header := "QUERY LOG" + filterHint
	return stylePanel.
		Width(logWidth).
		Height(m.height - 3).
		Render(lipgloss.JoinVertical(lipgloss.Left,
			header,
			"",
			m.logVP.View(),
		))
}

// ── Stats panel ──────────────────────────────────────────────────────────────

func renderStatsPanel(m *Model) string {
	s := m.stats
	statWidth := max(m.width/2, 30)
	barW := max(statWidth-26, 3)

	hitRate := 0.0
	if s.Total > 0 {
		hitRate = float64(s.Hits) / float64(s.Total) * 100
	}

	var sb strings.Builder
	sb.WriteString("OVERVIEW\n\n")
	fmt.Fprintf(&sb, "%s%s\n", styleStatLabel.Render("Total:"), styleStatValue.Render(strconv.FormatInt(s.Total, 10)))
	fmt.Fprintf(&sb, "%s%s\n", styleStatLabel.Render("QPS:"), styleStatValue.Render(strconv.FormatInt(m.currentQPS, 10)+"/s"))
	fmt.Fprintf(&sb, "%s%s\n", styleStatLabel.Render("Hit Rate:"), styleStatValue.Render(fmt.Sprintf("%.1f%%", hitRate)))
	fmt.Fprintf(&sb, "%s%s\n", styleStatLabel.Render("Avg Lat:"), styleStatValue.Render(fmt.Sprintf("%.1fms", s.AvgMS)))
	fmt.Fprintf(&sb, "%s%s\n\n", styleStatLabel.Render("Cache:"), styleStatValue.Render(strconv.FormatInt(s.Entries, 10)))

	// RCODE
	sb.WriteString("RCODE\n")
	for _, rc := range []struct {
		name  string
		count int64
	}{
		{"NOERR", s.NOERR},
		{"NXDOM", s.NXDomain},
		{"SRVFAIL", s.ServFail},
		{"FORMERR", s.FormErr},
		{"REFUSED", s.Refused},
		{"NOTIMP", s.NotImp},
	} {
		ratio := 0.0
		if s.Total > 0 {
			ratio = float64(rc.count) / float64(s.Total)
		}
		fmt.Fprintf(&sb, "%-7s %s %5.1f%%\n", rc.name, barChart(barW, ratio), ratio*100)
	}
	sb.WriteString("\n")

	// Protocol
	sb.WriteString("PROTOCOL\n")
	for _, p := range []struct {
		name  string
		count int64
	}{
		{"UDP", s.UDP},
		{"TCP", s.TCP},
		{"DoT", s.TLS},
		{"DoQ", s.QUIC},
		{"DoH", s.HTTPS},
		{"DoH3", s.HTTP3},
		{"DTLS", s.DTLS},
		{"DNSCrypt", s.DNSCrypt},
		{"TLCP", s.TLCP},
	} {
		ratio := 0.0
		if s.Total > 0 {
			ratio = float64(p.count) / float64(s.Total)
		}
		if p.count == 0 {
			continue
		}
		fmt.Fprintf(&sb, "%-9s %s %5.1f%%\n", p.name, barChart(barW, ratio), ratio*100)
	}
	sb.WriteString("\n")

	// DNSSEC + poison
	sb.WriteString("DNSSEC\n")
	if s.Total > 0 {
		fmt.Fprintf(&sb, "%s%s\n", styleStatLabel.Render("Secure:"), styleStatValue.Render(fmt.Sprintf("%d (%.1f%%)", s.Secure, float64(s.Secure)/float64(s.Total)*100)))
		fmt.Fprintf(&sb, "%s%s\n", styleStatLabel.Render("Insecure:"), styleStatValue.Render(strconv.FormatInt(s.Insecure, 10)))
		fmt.Fprintf(&sb, "%s%s\n", styleStatLabel.Render("Bogus:"), styleStatValue.Render(strconv.FormatInt(s.Bogus, 10)))
	}
	fmt.Fprintf(&sb, "%s%s\n", styleStatLabel.Render("Poisoned:"), styleStatValue.Render(strconv.FormatInt(s.Poisoned, 10)))

	return stylePanel.
		Width(statWidth).
		Height(m.height - 3).
		Render(sb.String())
}
