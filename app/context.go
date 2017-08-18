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

	"github.com/jmoiron/sqlx"

	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/ory/hydra/sdk"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
)

const (
	CookieKeySession       = "mokey-sessck"
	CookieKeyAuthenticated = "authenticated"
	CookieKeySID           = "sid"
	CookieKeyUser          = "user"
	CookieKeyWYAF          = "wyaf"
	ContextKeyUser         = "user"
	TokenRegex             = `[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\-\_\.]+`
	ResetSalt              = "resetpw"
	AccountSetupSalt       = "acctsetup"
)

type AppContext struct {
	DB          *sqlx.DB
	HydraClient *sdk.Client
	Tmpldir     string
	cookieStore *sessions.CookieStore
	templates   map[string]*template.Template
	emails      map[string]*template.Template
}

func NewAppContext() (*AppContext, error) {
	db, err := model.NewDB(viper.GetString("driver"), viper.GetString("dsn"))
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
		if base != "layout.html" && base != "otp-info.html" {
			templates[base] = template.Must(template.New("layout").ParseFiles(t,
				tmpldir+"/layout.html",
				tmpldir+"/otp-info.html"))
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
	app.DB = db
	app.cookieStore = sessions.NewCookieStore([]byte(viper.GetString("auth_key")), []byte(viper.GetString("enc_key")))
	app.cookieStore.Options.Secure = !viper.GetBool("develop")
	app.cookieStore.MaxAge(0)
	app.templates = templates
	app.emails = emails

	if viper.IsSet("hydra_cluster_url") {
		app.HydraClient, err = sdk.Connect(
			sdk.ClientID(viper.GetString("hydra_client_id")),
			sdk.ClientSecret(viper.GetString("hydra_client_secret")),
			sdk.SkipTLSVerify(viper.GetBool("develop")),
			sdk.Scopes("hydra.keys.get"),
			sdk.ClusterURL(viper.GetString("hydra_cluster_url")))
	}

	if err != nil {
		log.Fatal(err)
	}

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

// Get WYAF from session
func (app *AppContext) GetWYAF(session *sessions.Session) string {
	defaultLocation := "/"

	wyaf := session.Values[CookieKeyWYAF]
	if wyaf == nil {
		return defaultLocation
	}

	if _, ok := wyaf.(string); !ok {
		return defaultLocation
	}

	return wyaf.(string)
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
