package tui

import "charm.land/lipgloss/v2"

// Color scheme — dark background, cyan/blue accents (matches project banner).
// Color values are adaptively mapped by lipgloss to true color / 256 / ANSI.
const (
	colorBg      = "0"  // black
	colorFg      = "15" // white
	colorDim     = "8"  // bright black (gray)
	colorAccent  = "14" // bright cyan
	colorHit     = "10" // bright green
	colorMiss    = "12" // bright blue
	colorStale   = "11" // bright yellow
	colorZone    = "14" // bright cyan
	colorError   = "9"  // bright red
	colorBlocked = "13" // bright magenta
)

var (
	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(colorAccent)).
			Padding(0, 1)

	stylePanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(colorDim)).
			Padding(1)

	styleStatLabel = lipgloss.NewStyle().
			Foreground(lipgloss.Color(colorDim)).
			Width(10)

	styleStatValue = lipgloss.NewStyle().
			Foreground(lipgloss.Color(colorFg)).
			Bold(true)

	styleFooter = lipgloss.NewStyle().
			Foreground(lipgloss.Color(colorDim)).
			Background(lipgloss.Color(colorBg)).
			Padding(0, 1)

	styleHelp = lipgloss.NewStyle().
			Foreground(lipgloss.Color(colorDim))

	styleBarFill = lipgloss.NewStyle().
			Foreground(lipgloss.Color(colorMiss))

	styleBarBg = lipgloss.NewStyle().
			Foreground(lipgloss.Color(colorDim))

	// Result badge colors — keyed by result type string.
	resultBadgeStyles = map[string]lipgloss.Style{
		"hit":     lipgloss.NewStyle().Foreground(lipgloss.Color(colorHit)).Bold(true),
		"miss":    lipgloss.NewStyle().Foreground(lipgloss.Color(colorMiss)).Bold(true),
		"stale":   lipgloss.NewStyle().Foreground(lipgloss.Color(colorStale)).Bold(true),
		"zone":    lipgloss.NewStyle().Foreground(lipgloss.Color(colorZone)).Bold(true),
		"error":   lipgloss.NewStyle().Foreground(lipgloss.Color(colorError)).Bold(true),
		"blocked": lipgloss.NewStyle().Foreground(lipgloss.Color(colorBlocked)).Bold(true),
	}
)

// resultBadge returns a colored, fixed-width badge for the query result type.
func resultBadge(result string) string {
	s, ok := resultBadgeStyles[result]
	if !ok {
		return lipgloss.NewStyle().Foreground(lipgloss.Color(colorFg)).Bold(true).Width(7).Render(result)
	}
	return s.Width(7).Render(result)
}

// barChart returns a horizontal bar with the given ratio (0.0–1.0) and label.
func barChart(width int, ratio float64) string {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	if width < 3 {
		width = 3
	}
	filled := int(ratio * float64(width))
	empty := width - filled
	bar := ""
	if filled > 0 {
		bar += styleBarFill.Render(repeatRune('█', filled))
	}
	if empty > 0 {
		bar += styleBarBg.Render(repeatRune('█', empty))
	}
	return bar
}

func repeatRune(r rune, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = r
	}
	return string(b)
}
