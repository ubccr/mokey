package server

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
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
	templates map[string]*template.Template
}

func NewTemplateRenderer() (*TemplateRenderer, error) {
	tmpl := make(map[string]*template.Template)

	localLayout := ""
	localHeader := ""
	localFooter := ""

	localTemplates, err := filepath.Glob(filepath.Join(viper.GetString("templates_dir"), "*.html"))
	if err != nil {
		return nil, err
	}

	for _, file := range localTemplates {
		base := filepath.Base(file)
		if base == "layout.html" {
			localLayout = file
		}
		switch base {
		case "layout.html":
			localLayout = file
		case "header.html":
			localHeader = file
		case "footer.html":
			localFooter = file
		}
	}

	embedTemplates, err := fs.Glob(templateFiles, "templates/*.html")
	if err != nil {
		return nil, err
	}

	for _, file := range embedTemplates {
		base := filepath.Base(file)
		if base == "layout.html" || base == "header.html" || base == "footer.html" {
			continue
		}

		switch base {
		case "login.html", "404.html", "401.html", "500.html":
			tmpl[base] = template.Must(template.ParseFS(templateFiles, file)).Funcs(funcMap)
		default:
			tmpl[base] = template.Must(template.New("layout").Funcs(funcMap).ParseFS(templateFiles, file))
		}

		if localLayout != "" {
			template.Must(tmpl[base].ParseFiles(localLayout))
		} else {
			template.Must(tmpl[base].ParseFS(templateFiles, "templates/layout.html"))
		}
		if localHeader != "" {
			template.Must(tmpl[base].ParseFiles(localHeader))
		} else {
			template.Must(tmpl[base].ParseFS(templateFiles, "templates/header.html"))
		}

		if localFooter != "" {
			template.Must(tmpl[base].ParseFiles(localFooter))
		} else {
			template.Must(tmpl[base].ParseFS(templateFiles, "templates/footer.html"))
		}
	}

	for _, file := range localTemplates {
		base := filepath.Base(file)
		if base == "layout.html" || base == "header.html" || base == "footer.html" {
			continue
		}

		switch base {
		case "login.html", "404.html", "401.html", "500.html":
			tmpl[base] = template.Must(template.ParseFiles(file)).Funcs(funcMap)
		default:
			tmpl[base] = template.Must(template.New("layout").Funcs(funcMap).ParseFiles(file))
		}

		if localLayout != "" {
			template.Must(tmpl[base].ParseFiles(localLayout))
		} else {
			template.Must(tmpl[base].ParseFS(templateFiles, "templates/layout.html"))
		}
		if localHeader != "" {
			template.Must(tmpl[base].ParseFiles(localHeader))
		} else {
			template.Must(tmpl[base].ParseFS(templateFiles, "templates/header.html"))
		}

		if localFooter != "" {
			template.Must(tmpl[base].ParseFiles(localFooter))
		} else {
			template.Must(tmpl[base].ParseFS(templateFiles, "templates/footer.html"))
		}
	}

	// Process partials
	embedPartials, err := fs.Glob(templateFiles, "templates/partials/*.html")
	if err != nil {
		return nil, err
	}

	for _, file := range embedPartials {
		base := filepath.Base(file)
		tmpl["partials/"+base] = template.Must(template.ParseFS(templateFiles, file)).Funcs(funcMap)
	}

	localPartials, err := filepath.Glob(filepath.Join(viper.GetString("templates_dir"), "partials/*.html"))
	if err != nil {
		return nil, err
	}

	for _, file := range localPartials {
		base := filepath.Base(file)
		tmpl["partial/"+base] = template.Must(template.ParseFiles(file)).Funcs(funcMap)
	}

	t := &TemplateRenderer{
		templates: tmpl,
	}

	return t, nil
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	if _, ok := t.templates[name]; !ok {
		return fmt.Errorf("Template not found: %s", name)
	}

	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}

	if strings.HasPrefix(name, "partials/") {
		return t.templates[name].Execute(w, data)
	}

	switch name {
	case "login.html", "404.html", "401.html", "500.html":
		return t.templates[name].Execute(w, data)
	default:
		return t.templates[name].ExecuteTemplate(w, "layout", data)
	}

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
