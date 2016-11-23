// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"net"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/context"
	"github.com/justinas/nosurf"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/app"
)

// AuthRequired ensures the user has successfully completed the authentication
// process including any 2FA.
func AuthRequired(ctx *app.AppContext, next http.Handler) http.Handler {
	return LoginRequired(ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := ctx.GetSession(r)
		if err != nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		auth := session.Values[app.CookieKeyAuthenticated]

		if auth != nil && auth.(bool) {
			next.ServeHTTP(w, r)
			return
		}

		http.Redirect(w, r, "/auth/login", 302)
		return
	}))
}

// LoginRequired ensure the user has logged in and has a valid FreeIPA session.
// Stores the ipa.UserRecord in the request context
func LoginRequired(ctx *app.AppContext, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := ctx.GetSession(r)
		if err != nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		sid := session.Values[app.CookieKeySID]
		userRec := session.Values[app.CookieKeyUser]

		if sid == nil || userRec == nil {
			http.Redirect(w, r, "/auth/login", 302)
			return
		}

		if _, ok := userRec.(*ipa.UserRecord); !ok {
			log.Error("Invalid user record in session.")
			http.Redirect(w, r, "/auth/login", 302)
			return
		}

		user := userRec.(*ipa.UserRecord)

		c := app.NewIpaClient(false)
		c.SetSession(sid.(string))

		_, err = c.Ping()
		if err != nil {
			log.WithFields(log.Fields{
				"uid":   user.Uid,
				"error": err.Error(),
			}).Error("FreeIPA ping failed")
			logout(ctx, w, r)
			http.Redirect(w, r, "/auth/login", 302)
			return
		}

		context.Set(r, "user", user)
		context.Set(r, "ipa", c)

		next.ServeHTTP(w, r)
	})
}

func RateLimit(ctx *app.AppContext, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check if rate limiting is enabled
		if !viper.GetBool("rate_limit") {
			next.ServeHTTP(w, r)
			return
		}

		// only rate limit POST request
		if r.Method != "POST" {
			next.ServeHTTP(w, r)
			return
		}

		remoteIP := r.Header.Get("X-Forwarded-For")
		if len(remoteIP) == 0 {
			remoteIP, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
		path := r.URL.Path

		conn, err := redis.Dial("tcp", viper.GetString("redis"))
		if err != nil {
			log.WithFields(log.Fields{
				"path":     path,
				"remoteIP": remoteIP,
				"err":      err.Error(),
			}).Error("Failed connecting to redis server")
			next.ServeHTTP(w, r)
			return
		}
		defer conn.Close()

		current, err := redis.Int(conn.Do("INCR", path+remoteIP))
		if err != nil {
			log.WithFields(log.Fields{
				"path":     path,
				"remoteIP": remoteIP,
				"err":      err.Error(),
			}).Error("Failed to increment counter in redis")
			next.ServeHTTP(w, r)
			return
		}

		if current > viper.GetInt("max_requests") {
			log.WithFields(log.Fields{
				"path":     path,
				"remoteIP": remoteIP,
				"counter":  current,
			}).Warn("Too many connections")
			w.WriteHeader(429)
			return
		}

		if current == 1 {
			_, err := conn.Do("SETEX", path+remoteIP, viper.GetInt("rate_limit_expire"), 1)
			if err != nil {
				log.WithFields(log.Fields{
					"path":     path,
					"remoteIP": remoteIP,
					"err":      err.Error(),
				}).Error("Failed to set expiry on counter in redis")
			}
		}

		log.WithFields(log.Fields{
			"path":     path,
			"remoteIP": remoteIP,
			"counter":  current,
		}).Info("rate limiting")

		next.ServeHTTP(w, r)
	})
}

// Nosurf is a wrapper for justinas' csrf protection middleware
func Nosurf() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return nosurf.New(next)
	}
}
