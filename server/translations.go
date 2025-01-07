package server

import (
    "fmt"
    "io/fs"
    "path/filepath"
    "strings"

    "github.com/spf13/viper"
    log "github.com/sirupsen/logrus"
)

// Global variable to hold translations
var translations map[string]map[string]string

// getDefaultLanguage gets the default language from the configuration
// or use 'english' as fallback.
func getDefaultLanguage() string {
    defaultLang := viper.GetString("site.default_language")
    if defaultLang == "" {
        defaultLang = "english"
        log.Warnf("No default language configured, using 'english' as fallback.")
    }
    return defaultLang
}

// LoadTranslations loads translations from the specified directory
func LoadTranslations() error {
    translationsDir := viper.GetString("site.translations_dir")
    if translationsDir == "" {
        return fmt.Errorf("translations directory is not configured")
    }

    log.Debugf("Attempting to load translations from directory: %s", translationsDir)

    translations = make(map[string]map[string]string)

    err := filepath.WalkDir(translationsDir, func(path string, d fs.DirEntry, err error) error {
        if err != nil {
            log.Errorf("Error accessing file or directory %s: %v", path, err)
            return err
        }
        if !d.IsDir() && strings.HasSuffix(d.Name(), ".toml") {
            log.Debugf("Found translation file: %s", path)

            lang := strings.TrimSuffix(d.Name(), ".toml")
            v := viper.New()
            v.SetConfigFile(path)
            v.SetConfigType("toml")

            if err := v.ReadInConfig(); err != nil {
                log.Errorf("Failed to parse translation file %s: %v", path, err)
                return fmt.Errorf("failed to parse translation file %s: %w", path, err)
            }

            langTranslations := make(map[string]string)
            for _, key := range v.AllKeys() {
                langTranslations[key] = v.GetString(key)
            }

            translations[lang] = langTranslations
            log.Debugf("Loaded translations for language %s", lang)
        }
        return nil
    })

    if err != nil {
        log.Errorf("Failed to load translations: %v", err)
        return fmt.Errorf("failed to load translations: %w", err)
    }

    return nil
}

// Translate fetches the translation for a key in the specified language
// with a fallback to the default language ('english') if not found.
func Translate(lang, key string) string {
    // If no language is specified, use the default language
    if lang == "" {
        lang = getDefaultLanguage()
    }

    // Try the translation in the specified language
    if langTranslations, ok := translations[lang]; ok {
        if value, ok := langTranslations[key]; ok {
            return value
        }
        log.Warnf("Translation key '%s' not found in language '%s'", key, lang)
    } else {
        log.Warnf("No translations found for language '%s'", lang)
    }

    // If the translation is not found in the specified language, try the default language
    defaultLang := getDefaultLanguage()
    if lang != defaultLang {
        if defaultLangTranslations, ok := translations[defaultLang]; ok {
            if value, ok := defaultLangTranslations[key]; ok {
                return value
            }
        }
    }

    log.Warnf("Falling back to key '%s' as translation", key)
    return key
}
