package server

import (
	"embed"
	"html/template"
	"io"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

//go:embed templates
var templateFiles embed.FS

// Template functions
var funcMap = template.FuncMap{
	"uri": URI,
}

type TemplateRenderer struct {
	templates *template.Template
}

func NewTemplateRenderer() (*TemplateRenderer, error) {

	tmpl, err := template.ParseFS(templateFiles, "templates/*.html")
	if err != nil {
		return nil, err
	}

	localTemplatePath := filepath.Join(viper.GetString("templates_dir"), "*.html")
	localTemplates, err := filepath.Glob(localTemplatePath)
	if err != nil {
		return nil, err
	}

	if len(localTemplates) > 0 {
		tmpl, err = tmpl.ParseGlob(localTemplatePath)
		if err != nil {
			return nil, err
		}
	}

	tmpl.Funcs(funcMap)

	t := &TemplateRenderer{
		templates: tmpl,
	}

	return t, nil
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}

	return t.templates.ExecuteTemplate(w, name, data)
}

func URI(c echo.Context, name string) string {
	if strings.HasPrefix(name, "/static") || strings.HasPrefix(name, "/auth/captcha/") {
		return name
	}

	if c != nil {
		return c.Echo().Reverse(name)
	}

	log.WithFields(log.Fields{
		"name": name,
	}).Error("Failed to build URI. Echo context nil")

	return name
}
