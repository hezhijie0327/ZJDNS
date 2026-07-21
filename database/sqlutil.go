package database

import "strings"

// BoolToInt converts a bool to 0 or 1 for SQLite INTEGER columns.
func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// JoinPlaceholders joins string parts with a separator, used for building
// SQL IN-clause placeholders.
func JoinPlaceholders(parts []string, sep string) string {
	return strings.Join(parts, sep)
}
