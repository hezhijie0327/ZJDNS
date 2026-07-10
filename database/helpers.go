package database

// BoolToInt converts a bool to 0 or 1 for SQLite INTEGER columns.
func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// JoinPlaceholders joins string parts with a separator, used for building
// parameterized SQL IN-clauses and VALUES lists.
func JoinPlaceholders(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	total := 0
	for _, p := range parts {
		total += len(p) + len(sep)
	}
	b := make([]byte, 0, total-len(sep))
	b = append(b, parts[0]...)
	for _, p := range parts[1:] {
		b = append(b, sep...)
		b = append(b, p...)
	}
	return string(b)
}
