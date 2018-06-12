package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/mokey/model"
	"github.com/ubccr/mokey/util"
)

func init() {
	viper.SetDefault("port", 8080)
	viper.SetDefault("min_passwd_len", 8)
	viper.SetDefault("min_passwd_classes", 2)
	viper.SetDefault("develop", false)
	viper.SetDefault("pgp_sign", false)
	viper.SetDefault("force_2fa", true)
	viper.SetDefault("require_question_pwreset", true)
	viper.SetDefault("smtp_host", "localhost")
	viper.SetDefault("smtp_port", 25)
	viper.SetDefault("email_link_base", "http://localhost")
	viper.SetDefault("email_from", "helpdesk@example.com")
	viper.SetDefault("email_prefix", "mokey")
	viper.SetDefault("setup_max_age", 86400)
	viper.SetDefault("reset_max_age", 3600)
	viper.SetDefault("max_attempts", 10)
	viper.SetDefault("bind", "")
	viper.SetDefault("driver", "mysql")
	viper.SetDefault("dsn", "/mokey?parseTime=true")
	viper.SetDefault("rate_limit", false)
	viper.SetDefault("redis", ":6379")
	viper.SetDefault("max_requests", 15)
	viper.SetDefault("rate_limit_expire", 3600)

	//gob.Register(&ipa.UserRecord{})
	//gob.Register(&ipa.IpaDateTime{})
	//gob.Register(&model.ApiKey{})
}

// Render custom error templates if available
func HTTPErrorHandler(err error, c echo.Context) {
	code := http.StatusInternalServerError
	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
	}

	if code == http.StatusNotFound {
		log.WithFields(log.Fields{
			"path": c.Request().URL,
			"ip":   c.RealIP(),
		}).Error("Requested path not found")
	}

	errorPage := fmt.Sprintf("%d.html", code)
	if err := c.Render(code, errorPage, nil); err != nil {
		c.Logger().Error(err)
	}

	c.Logger().Error(err)
}

// Start web server
func Run() error {
	e := echo.New()

	tmplDir := util.GetTemplateDir()
	log.Infof("Using template dir: %s", tmplDir)

	renderer, err := NewTemplateRenderer(tmplDir)
	if err != nil {
		log.Fatal(err)
	}

	e.Renderer = renderer
	e.Static("/static", filepath.Join(tmplDir, "static"))
	e.HTTPErrorHandler = HTTPErrorHandler
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "form:csrf",
	}))

	// Sessions
	cookieStore := sessions.NewCookieStore([]byte(viper.GetString("auth_key")), []byte(viper.GetString("enc_key")))
	cookieStore.Options.Secure = !viper.GetBool("develop")
	cookieStore.MaxAge(0)
	e.Use(session.Middleware(cookieStore))

	db, err := model.NewDB(viper.GetString("driver"), viper.GetString("dsn"))
	if err != nil {
		return err
	}

	h, err := NewHandler(db)
	if err != nil {
		return err
	}

	h.SetupRoutes(e)

	log.Printf("IPA server: %s", viper.GetString("ipahost"))

	// Redirect to https if enabled
	if viper.IsSet("insecure_redirect_port") && viper.IsSet("insecure_redirect_host") {
		log.Infof("Redirecting insecure http requests on port %d to https://%s:%d",
			viper.GetInt("insecure_redirect_port"),
			viper.GetString("insecure_redirect_host"),
			viper.GetInt("port"))

		srv := &http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  120 * time.Second,
			Addr:         fmt.Sprintf("%s:%d", viper.GetString("bind"), viper.GetInt("insecure_redirect_port")),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Connection", "close")
				url := fmt.Sprintf("https://%s:%d%s", viper.GetString("insecure_redirect_host"), viper.GetInt("port"), req.URL.String())
				http.Redirect(w, req, url, http.StatusMovedPermanently)
			}),
		}
		go func() { log.Fatal(srv.ListenAndServe()) }()
	}

	s := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", viper.GetString("bind"), viper.GetInt("port")),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	if certFile != "" && keyFile != "" {
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		s.TLSConfig = cfg
		s.TLSConfig.Certificates = make([]tls.Certificate, 1)
		s.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}

		log.Printf("Running on https://%s:%d", viper.GetString("bind"), viper.GetInt("port"))
	} else {
		log.Warn("**WARNING*** SSL/TLS not enabled. HTTP communication will not be encrypted and vulnerable to snooping.")
		log.Printf("Running on http://%s:%d", viper.GetString("bind"), viper.GetInt("port"))
	}

	return e.StartServer(s)
}
