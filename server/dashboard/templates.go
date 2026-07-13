package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed templates/*
var templatesFS embed.FS

// handleIndex serves the embedded single-page application at /.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	subFS, err := fs.Sub(templatesFS, "templates")
	if err != nil {
		http.Error(w, "templates not found", http.StatusInternalServerError)
		return
	}
	http.FileServer(http.FS(subFS)).ServeHTTP(w, r)
}
