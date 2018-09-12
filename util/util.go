package util

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func GetTemplateDir() string {
	tmpldir := viper.GetString("templates")
	if len(tmpldir) == 0 {
		// default to directory of current executable
		path, err := filepath.EvalSymlinks(os.Args[0])
		if err != nil {
			log.Fatal(err)
		}
		dir, err := filepath.Abs(filepath.Dir(path))
		if err != nil {
			log.Fatal(err)
		}
		tmpldir = dir + "/templates"
	}

	return tmpldir
}
