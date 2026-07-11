package ruleset

import "os"

// readFile reads a file and returns its content. Used for CIDR and domain file imports.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: path from config, not user input
}
