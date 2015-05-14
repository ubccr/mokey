package main

import (
    "fmt"
    "log"
    "os"
    "html/template"
    "path/filepath"
    "net/http"
    "github.com/jmoiron/sqlx"
    _ "github.com/go-sql-driver/mysql"

    "github.com/Sirupsen/logrus"
    "github.com/carbocation/interpose"
    "github.com/spf13/viper"
    "github.com/gorilla/mux"
    "github.com/gorilla/schema"
    "github.com/gorilla/sessions"
    "github.com/ubccr/goipa"
)

const (
    MOKEY_COOKIE_SESSION = "mokey-session"
    MOKEY_COOKIE_SID     = "sid"
    MOKEY_COOKIE_USER    = "uid"
)

type Application struct {
    dsn           string
    db            *sqlx.DB
    cookieStore   *sessions.CookieStore
    decoder       *schema.Decoder
    templates     map[string]*template.Template
    tmpldir       string
}

func NewApplication() (*Application, error) {
    db, err := sqlx.Open(viper.GetString("driver"), viper.GetString("dsn"))
    if err != nil {
        return nil, err
    }

    err = db.Ping()
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
        tmpldir = dir
    }

    logrus.Printf("Using template dir: %s", tmpldir)

    tmpls, err := filepath.Glob(tmpldir + "/templates/*.html")
    if err != nil {
        log.Fatal(err)
    }

    templates := make(map[string]*template.Template)
    for _, t := range tmpls {
        base := filepath.Base(t)
        if base != "layout.html" {
            templates[base] = template.Must(template.New("layout").ParseFiles(t,
                                                        tmpldir + "/templates/layout.html"))
        }
    }

    app := &Application{}
    app.tmpldir = tmpldir
    app.db = db
    app.cookieStore = sessions.NewCookieStore([]byte(viper.GetString("secret")))
    app.decoder = schema.NewDecoder()
    //app.decoder.IgnoreUnknownKeys(true)
    app.templates = templates

    return app, nil
}

func (a *Application) NewIpaClient(withKeytab bool) (*ipa.Client) {
    c := &ipa.Client{Host: viper.GetString("ipahost")}
    if withKeytab {
        c.KeyTab = viper.GetString("keytab")
    }

    return c
}

func (a *Application) middlewareStruct() (*interpose.Middleware, error) {
    mw := interpose.New()
    mw.Use(Nosurf())

    mw.UseHandler(a.router())

    return mw, nil
}

func (a *Application) router() *mux.Router {
    router := mux.NewRouter()

    router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusNotFound)
        renderTemplate(w, a.templates["404.html"], nil)
    })
    router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(fmt.Sprintf("%s/static", a.tmpldir)))))
    router.Path("/auth/login").Handler(LoginHandler(a)).Methods("GET", "POST")
    router.Path("/").Handler(AuthRequired(a, IndexHandler(a))).Methods("GET", "POST")

    return router
}


func init() {
    viper.SetDefault("port", 8080)
    viper.SetDefault("bind", "")
    viper.SetDefault("secret", "change-me")
    viper.SetDefault("driver", "mysql")
    viper.SetDefault("dsn", "/mokey?parseTime=true")
    viper.SetDefault("ipahost", "localhost")
}

func Server() {
    app, err := NewApplication()
    if err != nil {
        logrus.Fatal(err.Error())
    }

    middle, err := app.middlewareStruct()
    if err != nil {
        logrus.Fatal(err.Error())
    }

    logrus.Printf("Running on http://%s:%d", viper.GetString("bind"), viper.GetInt("port"))

    http.Handle("/", middle)

    certFile := viper.GetString("cert")
    keyFile := viper.GetString("key")

    if certFile != "" && keyFile != "" {
        http.ListenAndServeTLS(fmt.Sprintf("%s:%d", viper.GetString("bind"), viper.GetInt("port")), certFile, keyFile, nil)
    } else {
        http.ListenAndServe(fmt.Sprintf("%s:%d", viper.GetString("bind"), viper.GetInt("port")), nil)
    }
}
