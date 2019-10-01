package server

import (
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	// Template functions
	funcMap = template.FuncMap{
		"uri": URI,
	}
)

// Template renderer
type TemplateRenderer struct {
	templates map[string]*template.Template
}

// Create a new template renderer. dir is the path to template files
func NewTemplateRenderer(dir string) (*TemplateRenderer, error) {
	t := &TemplateRenderer{
		templates: make(map[string]*template.Template),
	}

	tmpls, err := filepath.Glob(filepath.Join(dir, "*.html"))
	if err != nil {
		return nil, err
	}

	for _, file := range tmpls {
		base := filepath.Base(file)
		if base != "layout.html" && base != "otp-info.html" {
			t.templates[base] = template.Must(template.New("layout").Funcs(funcMap).ParseFiles(file,
				filepath.Join(dir, "layout.html"),
				filepath.Join(dir, "otp-info.html")))
		}
	}

	return t, nil
}

// Render renders a template
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	if _, ok := t.templates[name]; !ok {
		return fmt.Errorf("Template not found: %s", name)
	}

	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["ctx"] = c
		viewContext["apiEnabled"] = viper.GetBool("enable_api_keys")
	}

	return t.templates[name].ExecuteTemplate(w, "layout", data)
}

func URI(c echo.Context, name string) string {
	if strings.HasPrefix(name, "/static") || strings.HasPrefix(name, "/auth/captcha/") {
		return Path(name)
	}

	if c != nil {
		return c.Echo().Reverse(name)
	}

	log.WithFields(log.Fields{
		"name": name,
	}).Error("Failed to build URI. Echo context nil")

	return name
}

func Path(path string) string {
	if viper.IsSet("path_prefix") {
		if path == "/" {
			path = ""
		}
		return viper.GetString("path_prefix") + path
	}

	return path
}
