// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/gob"
	"fmt"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/carbocation/interpose"
	"github.com/go-ini/ini"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/handlers"
)

func init() {
	viper.SetDefault("port", 8080)
	viper.SetDefault("min_passwd_len", 8)
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

func middlewareStruct(ctx *app.AppContext) *interpose.Middleware {
	mw := interpose.New()
	mw.Use(handlers.Nosurf())

	mw.UseHandler(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Referrer-Policy", "origin-when-cross-origin")
	}))

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

	// LoginRequired
	router.Path("/auth/2fa").Handler(handlers.LoginRequired(ctx, handlers.RateLimit(ctx, handlers.TwoFactorAuthHandler(ctx)))).Methods("GET", "POST")
	router.Path("/auth/setsec").Handler(handlers.LoginRequired(ctx, handlers.RateLimit(ctx, handlers.SetupQuestionHandler(ctx)))).Methods("GET", "POST")

	// AuthRequired
	router.Path("/changepw").Handler(handlers.AuthRequired(ctx, handlers.ChangePasswordHandler(ctx))).Methods("GET", "POST")
	router.Path("/sshpubkey").Handler(handlers.AuthRequired(ctx, handlers.SSHPubKeyHandler(ctx))).Methods("GET", "POST")
	router.Path("/sshpubkey/new").Handler(handlers.AuthRequired(ctx, handlers.NewSSHPubKeyHandler(ctx))).Methods("GET", "POST")
	router.Path("/2fa").Handler(handlers.AuthRequired(ctx, handlers.TwoFactorHandler(ctx))).Methods("GET", "POST")
	router.Path("/otptokens").Handler(handlers.AuthRequired(ctx, handlers.OTPTokensHandler(ctx))).Methods("GET", "POST")
	router.Path("/").Handler(handlers.AuthRequired(ctx, handlers.IndexHandler(ctx))).Methods("GET")

	mw.UseHandler(router)

	return mw
}

func Server() {
	ctx, err := app.NewAppContext()
	if err != nil {
		log.Fatal(err.Error())
	}

	middle := middlewareStruct(ctx)

	log.Printf("Running on http://%s:%d", viper.GetString("bind"), viper.GetInt("port"))
	log.Printf("IPA server: %s", viper.GetString("ipahost"))

	http.Handle("/", middle)

	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")

	if certFile != "" && keyFile != "" {
		http.ListenAndServeTLS(fmt.Sprintf("%s:%d", viper.GetString("bind"), viper.GetInt("port")), certFile, keyFile, nil)
	} else {
		log.Warn("**WARNING*** SSL/TLS not enabled. HTTP communication will not be encrypted and vulnerable to snooping.")
		http.ListenAndServe(fmt.Sprintf("%s:%d", viper.GetString("bind"), viper.GetInt("port")), nil)
	}
}
