// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package app

import (
	"bytes"
	"html/template"
	"net/http"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
	"github.com/jmoiron/sqlx"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
)

const (
	CookieKeySession       = "mokey-session"
	CookieKeyAuthenticated = "authenticated"
	CookieKeySID           = "sid"
	CookieKeyUser          = "user"
	CookieKeyOTP           = "otp"
	ContextKeyUser         = "user"
	TokenRegex             = `[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\-\_\.]+`
	ResetSalt              = "resetpw"
	AccountSetupSalt       = "acctsetup"
)

type AppContext struct {
	Db          *sqlx.DB
	Tmpldir     string
	dsn         string
	cookieStore *sessions.CookieStore
	templates   map[string]*template.Template
	emails      map[string]*template.Template
}

func NewDb() (*sqlx.DB, error) {
	db, err := sqlx.Open(viper.GetString("driver"), viper.GetString("dsn"))
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func NewAppContext() (*AppContext, error) {
	db, err := NewDb()
	if err != nil {
		return nil, err
	}

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

	log.Printf("Using template dir: %s", tmpldir)

	tmpls, err := filepath.Glob(tmpldir + "/*.html")
	if err != nil {
		log.Fatal(err)
	}

	templates := make(map[string]*template.Template)
	for _, t := range tmpls {
		base := filepath.Base(t)
		if base != "layout.html" {
			templates[base] = template.Must(template.New("layout").ParseFiles(t,
				tmpldir+"/layout.html"))
		}
	}

	tmpls, err = filepath.Glob(tmpldir + "/email/*.txt")
	if err != nil {
		log.Fatal(err)
	}

	emails := make(map[string]*template.Template)
	for _, t := range tmpls {
		base := filepath.Base(t)
		emails[base] = template.Must(template.New(base).ParseFiles(t))
	}

	app := &AppContext{}
	app.Tmpldir = tmpldir
	app.Db = db
	app.cookieStore = sessions.NewCookieStore([]byte(viper.GetString("secret_key")))
	app.templates = templates
	app.emails = emails

	return app, nil
}

func NewIpaClient(withKeytab bool) *ipa.Client {
	c := &ipa.Client{Host: viper.GetString("ipahost")}
	if withKeytab {
		c.KeyTab = viper.GetString("keytab")
	}

	return c
}

// Get the session
func (app *AppContext) GetSession(r *http.Request) (*sessions.Session, error) {
	session, err := app.cookieStore.Get(r, CookieKeySession)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("failed to get current session")
		return nil, err
	}

	return session, nil
}

// Get the user from the request context
func (app *AppContext) GetUser(r *http.Request) *ipa.UserRecord {
	if user := context.Get(r, ContextKeyUser); user != nil {
		return user.(*ipa.UserRecord)
	}

	log.Error("user not found in request context")
	return nil
}

// Render 404 template
func (app *AppContext) RenderNotFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)

	app.RenderTemplate(w, "404.html", nil)
}

// Render template t using template parameters in data.
func (app *AppContext) RenderTemplate(w http.ResponseWriter, name string, data interface{}) {
	t := app.templates[name]

	var buf bytes.Buffer
	err := t.ExecuteTemplate(&buf, "layout", data)

	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("failed to render template")
		http.Error(w, "Fatal error rendering template", http.StatusInternalServerError)
		return
	}

	buf.WriteTo(w)
}

// Render error template and write HTTP status
func (app *AppContext) RenderError(w http.ResponseWriter, status int) {
	w.WriteHeader(status)

	app.RenderTemplate(w, "error.html", nil)
}
