package server

import (
	"embed"
	"html/template"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"fmt"

	"github.com/dustin/go-humanize"
	"github.com/spf13/viper"
	log "github.com/sirupsen/logrus"
	"github.com/gofiber/fiber/v2"
)

//go:embed templates
var templateFiles embed.FS

// Template functions
var funcMap = template.FuncMap{
	"SplitSSHFP":        SplitSSHFP,
	"TimeAgo":           TimeAgo,
	"ConfigValueString": ConfigValueString,
	"ConfigValueBool":   ConfigValueBool,
	"AllowedDomains":    AllowedDomains,
	"BreakNewlines":     BreakNewlines,
	"Translate":         Translate,
}

type TemplateRenderer struct {
	templates *template.Template
}

func NewTemplateRenderer() (*TemplateRenderer, error) {
	// Laad vertalingen
	err := LoadTranslations()
	if err != nil {
		return nil, fmt.Errorf("failed to load translations: %w", err)
	}

	tmpl := template.New("")
	tmpl.Funcs(funcMap)
	tmpl, err = tmpl.ParseFS(templateFiles, "templates/*.html")
	if err != nil {
		return nil, err
	}

	// Add local templates if available
	if viper.IsSet("site.templates_dir") {
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
	// Same logic to check if "lang" is set and apply translation
	var dataMap map[string]interface{}
	switch v := data.(type) {
	case map[string]interface{}:
		dataMap = v
	case fiber.Map:
		dataMap = map[string]interface{}(v)
	default:
		log.Println("WARN: The provided data is not a map[string]interface{}, wrapping in map")
		dataMap = map[string]interface{}{"data": data}
	}

	defaultLang := "en"
	if viper.IsSet("site.default_language") {
		defaultLang = viper.GetString("site.default_language")
	}

	if lang, exists := dataMap["lang"]; !exists {
		log.Printf("DEBUG: 'lang' key not found, using default language '%s'", defaultLang)
		dataMap["lang"] = defaultLang
	} else {
		log.Debugf("DEBUG: Found 'lang' key with value: %v", lang)
	}

	return t.templates.ExecuteTemplate(w, name, dataMap)
}

func AllowedDomains() string {
	allowedDomains := viper.GetStringMapString("accounts.allowed_domains")

	i := 0
	domains := make([]string, len(allowedDomains))
	for d := range allowedDomains {
		domains[i] = d
		i++
	}

	sort.Strings(domains)

	return strings.Join(domains, ", ")
}

func ConfigValueString(key string) string {
	return viper.GetString(key)
}

func ConfigValueBool(key string) bool {
	return viper.GetBool(key)
}

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

func BreakNewlines(s string) template.HTML {
	return template.HTML(strings.Replace(template.HTMLEscapeString(s), "\n", "<br />", -1))
}
