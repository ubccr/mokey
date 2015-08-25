package main

import (
    "fmt"
    "log"
    "os"
    "bytes"
    "html/template"
    "encoding/gob"
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
    "gopkg.in/gomail.v2-unstable"
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
    emails        map[string]*template.Template
    tmpldir       string
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

func NewApplication() (*Application, error) {
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

    tmpls, err = filepath.Glob(tmpldir + "/templates/email/*.txt")
    if err != nil {
        log.Fatal(err)
    }

    emails := make(map[string]*template.Template)
    for _, t := range tmpls {
        base := filepath.Base(t)
        emails[base] = template.Must(template.New(base).ParseFiles(t))
    }

    app := &Application{}
    app.tmpldir = tmpldir
    app.db = db
    app.cookieStore = sessions.NewCookieStore([]byte(viper.GetString("secret")))
    app.decoder = schema.NewDecoder()
    //app.decoder.IgnoreUnknownKeys(true)
    app.templates = templates
    app.emails = emails

    return app, nil
}

func NewIpaClient(withKeytab bool) (*ipa.Client) {
    c := &ipa.Client{Host: viper.GetString("ipahost")}
    if withKeytab {
        c.KeyTab = viper.GetString("keytab")
    }

    return c
}

func (a *Application) SendEmail(email, subject, template string, data interface{}) (error) {
    logrus.WithFields(logrus.Fields{
        "email": email,
    }).Info("Sending email to user")

    t := a.emails[template]
    var buf bytes.Buffer
    err := t.ExecuteTemplate(&buf, template, data)

    if err != nil {
        return err
    }

    m := gomail.NewMessage()
    m.SetHeader("From", viper.GetString("email_from"))
    m.SetHeader("To", email)
    m.SetHeader("Subject", subject)

    m.SetBody("text/plain", buf.String())

    d := gomail.Dialer{Host: viper.GetString("smtp_host"), Port: viper.GetInt("smtp_port")}
    if err := d.DialAndSend(m); err != nil {
        return err
    }

    return nil
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
    router.Path("/auth/setup/{token:[0-9a-f]+}").Handler(SetupAccountHandler(a)).Methods("GET", "POST")
    router.Path("/auth/resetpw/{token:[0-9a-f]+}").Handler(ResetPasswordHandler(a)).Methods("GET", "POST")
    router.Path("/").Handler(AuthRequired(a, IndexHandler(a))).Methods("GET")

    return router
}


func init() {
    viper.SetDefault("port", 8080)
    viper.SetDefault("smtp_host", "localhost")
    viper.SetDefault("smtp_port", 25)
    viper.SetDefault("email_link_base", "http://localhost")
    viper.SetDefault("email_from", "helpdesk@example.com")
    viper.SetDefault("email_prefix", "mokey")
    viper.SetDefault("setup_max_age", 86400)
    viper.SetDefault("reset_max_age", 3600)
    viper.SetDefault("max_attempts", 10)
    viper.SetDefault("bind", "")
    viper.SetDefault("secret", "change-me")
    viper.SetDefault("driver", "mysql")
    viper.SetDefault("dsn", "/mokey?parseTime=true")
    viper.SetDefault("ipahost", "localhost")

    gob.Register(&ipa.UserRecord{})
    gob.Register(&ipa.IpaDateTime{})
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
