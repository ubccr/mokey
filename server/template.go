package server

import (
	"fmt"
	"html/template"
	"io"
	"path/filepath"

	"github.com/labstack/echo"
	"github.com/spf13/viper"
)

var (
	// Template functions
	funcMap = template.FuncMap{}
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
		viewContext["reverse"] = c.Echo().Reverse
		viewContext["apiEnabled"] = viper.GetBool("enable_api_keys")
	}

	return t.templates[name].ExecuteTemplate(w, "layout", data)
}
