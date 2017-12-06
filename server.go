// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"net/http"
	"time"

	"github.com/go-ini/ini"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/handlers"
	"github.com/ubccr/mokey/model"
	"github.com/urfave/negroni"
)

func init() {
	viper.SetDefault("port", 8080)
	viper.SetDefault("min_passwd_len", 8)
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

	gob.Register(&ipa.UserRecord{})
	gob.Register(&ipa.IpaDateTime{})
	gob.Register(&model.ApiKey{})

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

func middleware(ctx *app.AppContext) *negroni.Negroni {
	router := mux.NewRouter()

	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx.RenderNotFound(w)
	})

	// Public
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(fmt.Sprintf("%s/static", ctx.Tmpldir)))))
	router.Path("/auth/login").Handler(handlers.RateLimit(ctx, handlers.LoginHandler(ctx))).Methods("GET", "POST")
	router.Path("/auth/logout").Handler(handlers.LogoutHandler(ctx)).Methods("GET")
	router.Path("/auth/forgotpw").Handler(handlers.RateLimit(ctx, handlers.ForgotPasswordHandler(ctx))).Methods("GET", "POST")

	// Token required
	router.Path(fmt.Sprintf("/auth/setup/{token:%s}", app.TokenRegex)).Handler(handlers.SetupAccountHandler(ctx)).Methods("GET", "POST")
	router.Path(fmt.Sprintf("/auth/resetpw/{token:%s}", app.TokenRegex)).Handler(handlers.ResetPasswordHandler(ctx)).Methods("GET", "POST")

	// UserNameRequired
	router.Path("/auth/2fa").Handler(handlers.UserNameRequired(ctx, handlers.RateLimit(ctx, handlers.TwoFactorAuthHandler(ctx)))).Methods("GET", "POST")

	// LoginRequired
	router.Path("/auth/setsec").Handler(handlers.LoginRequired(ctx, handlers.RateLimit(ctx, handlers.SetupQuestionHandler(ctx)))).Methods("GET", "POST")

	// AuthRequired
	router.Path("/changepw").Handler(handlers.AuthRequired(ctx, handlers.ChangePasswordHandler(ctx))).Methods("GET", "POST")
	router.Path("/sshpubkey").Handler(handlers.AuthRequired(ctx, handlers.SSHPubKeyHandler(ctx))).Methods("GET", "POST")
	router.Path("/sshpubkey/new").Handler(handlers.AuthRequired(ctx, handlers.NewSSHPubKeyHandler(ctx))).Methods("GET", "POST")
	router.Path("/2fa").Handler(handlers.AuthRequired(ctx, handlers.TwoFactorHandler(ctx))).Methods("GET", "POST")
	router.Path("/otptokens").Handler(handlers.AuthRequired(ctx, handlers.OTPTokensHandler(ctx))).Methods("GET", "POST")
	router.Path("/consent").Handler(handlers.AuthRequired(ctx, handlers.RateLimit(ctx, handlers.ConsentHandler(ctx)))).Methods("GET", "POST")
	router.Path("/apikey").Handler(handlers.AuthRequired(ctx, handlers.ApiKeyHandler(ctx))).Methods("GET", "POST")
	router.Path("/").Handler(handlers.AuthRequired(ctx, handlers.IndexHandler(ctx))).Methods("GET")

	n := negroni.New(negroni.NewRecovery())
	n.Use(negroni.HandlerFunc(func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		rw.Header().Set("Referrer-Policy", "origin-when-cross-origin")
		rw.Header().Set("Strict-Transport-Security", "max-age=15768000;")
		next(rw, r)
	}))

	CSRF := csrf.Protect(
		[]byte(viper.GetString("auth_key")),
		csrf.FieldName(app.CSRFFieldName),
		csrf.CookieName("mokey-csrf"),
		csrf.Secure(!viper.GetBool("develop")))
	n.UseHandler(CSRF(router))

	return n
}

func Server() {
	ctx, err := app.NewAppContext()
	if err != nil {
		log.Fatal(err.Error())
	}

	middle := middleware(ctx)

	log.Printf("IPA server: %s", viper.GetString("ipahost"))

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

	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         fmt.Sprintf("%s:%d", viper.GetString("bind"), viper.GetInt("port")),
		Handler:      middle,
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

		srv.TLSConfig = cfg

		log.Printf("Running on https://%s:%d", viper.GetString("bind"), viper.GetInt("port"))
		log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
	} else {
		log.Warn("**WARNING*** SSL/TLS not enabled. HTTP communication will not be encrypted and vulnerable to snooping.")
		log.Printf("Running on http://%s:%d", viper.GetString("bind"), viper.GetInt("port"))
		log.Fatal(srv.ListenAndServe())
	}
}
