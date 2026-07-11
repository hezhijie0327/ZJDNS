package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"zjdns/database"
)

// RunSQL opens a SQLite cache database in read-only mode and runs a SQL
// query, printing results as an aligned columnar table (like sqlite3 -column
// -header).
func RunSQL(dbPath, query string) error {
	db, err := database.Open(dbPath, 0, database.Options{})
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// PRAGMA query_only=ON prevents any write operations on this connection.
	if _, err := db.SQ.Exec("PRAGMA query_only = ON"); err != nil {
		return fmt.Errorf("set query_only: %w", err)
	}

	rows, err := db.SQ.Query(query)
	if err != nil {
		return fmt.Errorf("query error: %w", err)
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("columns error: %w", err)
	}

	// Collect all rows as strings, tracking max width per column.
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = len(c)
	}
	var allRows [][]string

	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
			continue
		}
		strs := make([]string, len(cols))
		for i, v := range vals {
			strs[i] = valStr(v)
			if len(strs[i]) > widths[i] {
				widths[i] = len(strs[i])
			}
		}
		allRows = append(allRows, strs)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows error: %w", err)
	}

	// Print header
	printRow(cols, widths)
	// Print separator
	seps := make([]string, len(cols))
	for i, w := range widths {
		seps[i] = strings.Repeat("-", w)
	}
	printRow(seps, widths)
	// Print data
	for _, row := range allRows {
		printRow(row, widths)
	}

	fmt.Fprintf(os.Stderr, "%d row(s)\n", len(allRows))
	return nil
}

func valStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(t)
	default:
		return fmt.Sprint(t)
	}
}

func printRow(cols []string, widths []int) {
	parts := make([]string, len(cols))
	for i, s := range cols {
		parts[i] = fmt.Sprintf("%-*s", widths[i], s)
	}
	fmt.Println(strings.Join(parts, "  "))
}

// RunSQLRW opens a SQLite cache database in read-write mode and executes a
// SQL statement (INSERT, UPDATE, DELETE, DROP, ALTER, etc.). Prompts for
// confirmation before executing, showing the full statement.
func RunSQLRW(dbPath, query string) error {
	fmt.Fprintf(os.Stderr, "Statement: %s\n", query)
	fmt.Fprintf(os.Stderr, "Execute? [y/N] ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return fmt.Errorf("no input")
	}
	resp := strings.TrimSpace(scanner.Text())
	if resp != "y" && resp != "Y" {
		return fmt.Errorf("aborted")
	}

	db, err := database.Open(dbPath, 0, database.Options{})
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	result, err := db.SQ.Exec(query)
	if err != nil {
		return fmt.Errorf("exec error: %w", err)
	}

	n, _ := result.RowsAffected()
	fmt.Fprintf(os.Stderr, "%d row(s) affected\n", n)
	return nil
}
