package server

import (
	"embed"
	"html/template"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/spf13/viper"
)

//go:embed templates
var templateFiles embed.FS

// Template functions
var funcMap = template.FuncMap{
	"SplitSSHFP": SplitSSHFP,
	"TimeAgo":    TimeAgo,
}

type TemplateRenderer struct {
	templates *template.Template
}

func NewTemplateRenderer() (*TemplateRenderer, error) {

	tmpl := template.New("")
	tmpl.Funcs(funcMap)
	tmpl, err := tmpl.ParseFS(templateFiles, "templates/*.html")
	if err != nil {
		return nil, err
	}

	localTemplatePath := filepath.Join(viper.GetString("site.templates_dir"), "*.html")
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

func (t *TemplateRenderer) Load() error {
	return nil
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, layouts ...string) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

/*
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}

	return t.templates.ExecuteTemplate(w, name, data)
}
*/

func TimeAgo(t time.Time) string {
	return humanize.Time(t)
}

func SplitSSHFP(fp string) []string {
	if fp == "" {
		return []string{"", "", ""}
	}

	parts := strings.Split(fp, " ")
	if len(parts) == 1 {
		return []string{parts[0], "", ""}
	}

	if len(parts) == 2 {
		return []string{parts[0], parts[1], ""}
	}

	parts[2] = strings.TrimLeft(parts[2], "(")
	parts[2] = strings.TrimRight(parts[2], ")")
	return parts
}
