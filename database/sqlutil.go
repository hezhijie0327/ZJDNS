package database

// BoolToInt converts a bool to 0 or 1 for SQLite INTEGER columns.
func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
