// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"net"
	"net/http"
	"strings"

	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/context"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/model"
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
		// Check if consent endpoint and Api Key was given
		accept := r.Header.Get("Accept")
		auth := strings.Split(r.Header.Get("Authorization"), " ")
		if strings.HasPrefix(r.URL.String(), "/consent") && strings.Contains(accept, "application/json") && len(auth) == 2 && strings.ToLower(auth[0]) == "bearer" && len(auth[1]) > 0 {
			ApiKeyRequired(ctx, auth[1], w, r, next)
			return
		}

		session, err := ctx.GetSession(r)
		if err != nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		if !strings.HasPrefix(r.URL.String(), "/auth") {
			query := r.URL.Query().Encode()
			if len(query) > 0 {
				session.Values[app.CookieKeyWYAF] = r.URL.Path + "?" + query
			} else {
				session.Values[app.CookieKeyWYAF] = r.URL.Path
			}
			log.WithFields(log.Fields{
				"wyaf": session.Values[app.CookieKeyWYAF],
			}).Info("Redirect URL")
			session.Save(r, w)
		}

		sid := session.Values[app.CookieKeySID]
		user := session.Values[app.CookieKeyUser]

		if sid == nil || user == nil {
			http.Redirect(w, r, "/auth/login", 302)
			return
		}

		if _, ok := user.(string); !ok {
			logout(ctx, w, r)
			log.Error("Invalid user record in session.")
			http.Redirect(w, r, "/auth/login", 302)
			return
		}

		c := app.NewIpaClient(false)
		c.SetSession(sid.(string))

		userRec, err := c.UserShow(user.(string))
		if err != nil {
			log.WithFields(log.Fields{
				"uid":              user,
				"ipa_client_error": err,
			}).Error("Failed to fetch user info from FreeIPA")
			http.Redirect(w, r, "/auth/login", 302)
			return
		}

		context.Set(r, app.ContextKeyUser, userRec)
		context.Set(r, "ipa", c)

		next.ServeHTTP(w, r)
	})
}

// UserNameRequired ensure the user has submitted a valid username.
func UserNameRequired(ctx *app.AppContext, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := ctx.GetSession(r)
		if err != nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		user := session.Values[app.CookieKeyUser]

		if user == nil {
			logout(ctx, w, r)
			http.Redirect(w, r, "/auth/login", 302)
			return
		}

		if _, ok := user.(string); !ok {
			logout(ctx, w, r)
			log.Error("Invalid user record in session.")
			http.Redirect(w, r, "/auth/login", 302)
			return
		}

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

func ApiKeyRequired(ctx *app.AppContext, keyString string, w http.ResponseWriter, r *http.Request, next http.Handler) {
	key, err := model.FetchApiKey(ctx.DB, keyString)
	if err != nil {
		log.WithFields(log.Fields{
			"key":   keyString,
			"error": err,
		}).Error("Failed to fetch api key")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Check api client is enabled in config
	if _, ok := ctx.ApiClients[key.ClientID]; !ok {
		log.WithFields(log.Fields{
			"key":       key.Key,
			"user":      key.UserName,
			"client_id": key.ClientID,
		}).Error("Api client is not enabled in mokey.yaml")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	session, err := ctx.GetSession(r)
	if err != nil {
		log.WithFields(log.Fields{
			"key":   keyString,
			"error": err,
		}).Error("Failed to fetch session")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = model.RefreshApiKey(ctx.DB, key)
	if err != nil {
		log.WithFields(log.Fields{
			"key":   keyString,
			"error": err,
		}).Error("Failed to save api key")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userRec, err := checkUser(key.UserName)
	if err != nil {
		log.WithFields(log.Fields{
			"key":   keyString,
			"user":  key.UserName,
			"error": err,
		}).Error("Failed to fetch user from ipa")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	session.Values[app.CookieKeyUser] = key.UserName
	session.Values[app.CookieKeyAuthenticated] = true
	context.Set(r, app.ContextKeyUser, userRec)
	context.Set(r, app.ContextKeyApi, key)

	err = session.Save(r, w)
	if err != nil {
		log.WithFields(log.Fields{
			"key":   keyString,
			"user":  key.UserName,
			"error": err,
		}).Error("Failed to save session")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	next.ServeHTTP(w, r)
}
