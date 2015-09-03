// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package main

import (
    "fmt"
    "time"
    "log"
    "crypto"
    "os"
    "bytes"
    "net/smtp"
    "net/textproto"
    "mime/multipart"
    "mime/quotedprintable"
    "html/template"
    "encoding/gob"
    "path/filepath"
    "net/http"
    "github.com/jmoiron/sqlx"
    _ "github.com/go-sql-driver/mysql"

    "golang.org/x/crypto/openpgp"
    "golang.org/x/crypto/openpgp/packet"
    "github.com/Sirupsen/logrus"
    "github.com/carbocation/interpose"
    "github.com/spf13/viper"
    "github.com/gorilla/mux"
    "github.com/gorilla/schema"
    "github.com/gorilla/sessions"
    "github.com/ubccr/goipa"
    "github.com/go-ini/ini"
)

const (
    MOKEY_COOKIE_SESSION = "mokey-session"
    MOKEY_COOKIE_SID     = "sid"
    MOKEY_COOKIE_USER    = "uid"
    MAX_PASS_LENGTH      = 8
    TOKEN_REGEX          = `[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\-\_\.]+`
    RESET_SALT           = "resetpw"
    ACCOUNT_SETUP_SALT   = "acctsetup"
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
        tmpldir = dir + "/templates"
    }

    logrus.Printf("Using template dir: %s", tmpldir)

    tmpls, err := filepath.Glob(tmpldir + "/*.html")
    if err != nil {
        log.Fatal(err)
    }

    templates := make(map[string]*template.Template)
    for _, t := range tmpls {
        base := filepath.Base(t)
        if base != "layout.html" {
            templates[base] = template.Must(template.New("layout").ParseFiles(t,
                                                        tmpldir + "/layout.html"))
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

    app := &Application{}
    app.tmpldir = tmpldir
    app.db = db
    app.cookieStore = sessions.NewCookieStore([]byte(viper.GetString("secret_key")))
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

func quotedBody(body []byte) ([]byte, error) {
    var buf bytes.Buffer
    w := quotedprintable.NewWriter(&buf)
    _, err := w.Write(body)
    if err != nil {
        return nil, err
    }

    err = w.Close()
    if err != nil {
        return nil, err
    }

    return buf.Bytes(), nil
}

func sign(qtext []byte, header textproto.MIMEHeader) ([]byte, error) {
    var buf bytes.Buffer

    for k, vv := range header {
        for _, v := range vv {
            fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
        }
    }
    fmt.Fprintf(&buf, "\r\n")
    _, err := buf.Write(qtext)
    if err != nil {
        return nil, err
    }

    file, err := os.Open(viper.GetString("pgp_key"))
    if err != nil {
        return nil, err
    }

    keyring, err := openpgp.ReadArmoredKeyRing(file)
    if err != nil {
        return nil, err
    }

    signingKey := keyring[0]

    if signingKey.PrivateKey.Encrypted {
        err = signingKey.PrivateKey.Decrypt([]byte(viper.GetString("pgp_passphrase")))
        if err != nil {
            return nil, err
        }
    }

    var sig bytes.Buffer
    err = openpgp.ArmoredDetachSign(&sig, signingKey, &buf, &packet.Config{DefaultHash: crypto.SHA256})
    if err != nil {
        return nil, err
    }

    return sig.Bytes(), nil
}

func (a *Application) SendEmail(email, subject, template string, data map[string]interface{}) (error) {
    logrus.WithFields(logrus.Fields{
        "email": email,
    }).Info("Sending email to user")

    if data == nil {
        data = make(map[string]interface{})
    }

    data["date"] = time.Now()
    data["contact"] = viper.GetString("email_from")
    data["sig"] = viper.GetString("email_sig")

    t := a.emails[template]
    var text bytes.Buffer
    err := t.ExecuteTemplate(&text, template, data)
    if err != nil {
        return err
    }

    qtext, err := quotedBody(text.Bytes())
    if err != nil {
        return err
    }

    header := make(textproto.MIMEHeader)
    header.Set("Mime-Version", "1.0")
    header.Set("Date", time.Now().Format(time.RFC1123Z))
    header.Set("To", email)
    header.Set("Subject", subject)
    header.Set("From", viper.GetString("email_from"))
    header.Set("Content-Type", "text/plain; charset=UTF-8")
    header.Set("Content-Transfer-Encoding", "quoted-printable")

    body := qtext

    if viper.GetBool("pgp_sign") {
        header.Del("Content-Transfer-Encoding")

        mhead := make(textproto.MIMEHeader)
        mhead.Add("Content-Type", "text/plain; charset=UTF-8")
        mhead.Add("Content-Transfer-Encoding", "quoted-printable")
        sig, err := sign(qtext, mhead)
        if err != nil {
            return err
        }

        var multipartBody bytes.Buffer
        mp := multipart.NewWriter(&multipartBody)
        boundary := mp.Boundary()
        mw, err := mp.CreatePart(mhead)
        if err != nil {
            return err
        }
        _, err = mw.Write(qtext)
        if err != nil {
            return err
        }

        mw, err = mp.CreatePart(textproto.MIMEHeader(
            map[string][]string {
                "Content-Type": []string{"application/pgp-signature; name=signature.asc;"},
            }))
        if err != nil {
            return err
        }

        _, err = mw.Write(sig)
        if err != nil {
            return err
        }

        err = mp.Close()
        if err != nil {
            return err
        }

        header.Set("Content-Type", fmt.Sprintf(`multipart/signed; boundary="%s"; protocol="application/pgp-signature"; micalg="pgp-sha256"`, boundary))
        body = multipartBody.Bytes()
    }

    c, err := smtp.Dial(fmt.Sprintf("%s:%d",viper.GetString("smtp_host"), viper.GetInt("smtp_port")))
    if err != nil {
        return err
    }
    defer c.Close()

    c.Mail(viper.GetString("email_from"))
    c.Rcpt(email)

    wc, err := c.Data()
    if err != nil {
        return err
    }
    defer wc.Close()

    var buf bytes.Buffer
    for k, vv := range header {
        for _, v := range vv {
            fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
        }
    }
    fmt.Fprintf(&buf, "\r\n")

    if _, err = buf.WriteTo(wc); err != nil {
        return err
    }
    if _, err = wc.Write(body); err != nil {
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
    router.Path("/auth/login").Handler(RateLimit(a, LoginHandler(a))).Methods("GET", "POST")
    router.Path("/auth/logout").Handler(LogoutHandler(a)).Methods("GET")
    router.Path("/auth/forgotpw").Handler(RateLimit(a, ForgotPasswordHandler(a))).Methods("GET", "POST")
    router.Path(fmt.Sprintf("/auth/setup/{token:%s}", TOKEN_REGEX)).Handler(SetupAccountHandler(a)).Methods("GET", "POST")
    router.Path(fmt.Sprintf("/auth/resetpw/{token:%s}", TOKEN_REGEX)).Handler(ResetPasswordHandler(a)).Methods("GET", "POST")
    router.Path("/changepw").Handler(AuthRequired(a, ChangePasswordHandler(a))).Methods("GET", "POST")
    router.Path("/updatesec").Handler(AuthRequired(a, UpdateSecurityQuestionHandler(a))).Methods("GET", "POST")
    router.Path("/").Handler(AuthRequired(a, IndexHandler(a))).Methods("GET")

    return router
}


func init() {
    viper.SetDefault("port", 8080)
    viper.SetDefault("pgp_sign", false)
    viper.SetDefault("smtp_host", "localhost")
    viper.SetDefault("smtp_port", 25)
    viper.SetDefault("email_link_base", "http://localhost")
    viper.SetDefault("email_from", "helpdesk@example.com")
    viper.SetDefault("email_prefix", "mokey")
    viper.SetDefault("setup_max_age", 86400)
    viper.SetDefault("reset_max_age", 3600)
    viper.SetDefault("max_attempts", 10)
    viper.SetDefault("bind", "")
    viper.SetDefault("secret_key", "change-me")
    viper.SetDefault("driver", "mysql")
    viper.SetDefault("dsn", "/mokey?parseTime=true")
    viper.SetDefault("rate_limit", false)
    viper.SetDefault("redis", ":6379")
    viper.SetDefault("max_requests", 15)
    viper.SetDefault("rate_limit_expire", 3600)

    gob.Register(&ipa.UserRecord{})
    gob.Register(&ipa.IpaDateTime{})

    if !viper.IsSet("ipahost") {
        cfg, err := ini.Load("/etc/ipa/default.conf")
        if err != nil {
            viper.SetDefault("ipahost", "localhost")
            return
        }

        ipaServer, err := cfg.Section("global").GetKey("server")
        if err != nil {
            viper.SetDefault("ipahost", "localhost")
            return
        }

        viper.SetDefault("ipahost", ipaServer)
    }
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
    logrus.Printf("IPA server: %s", viper.GetString("ipahost"))

    http.Handle("/", middle)

    certFile := viper.GetString("cert")
    keyFile := viper.GetString("key")

    if certFile != "" && keyFile != "" {
        http.ListenAndServeTLS(fmt.Sprintf("%s:%d", viper.GetString("bind"), viper.GetInt("port")), certFile, keyFile, nil)
    } else {
        logrus.Warn("**WARNING*** SSL/TLS not enabled. HTTP communication will not be encrypted and vulnerable to snooping.")
        http.ListenAndServe(fmt.Sprintf("%s:%d", viper.GetString("bind"), viper.GetInt("port")), nil)
    }
}
