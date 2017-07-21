// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"database/sql"
	"errors"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/model"
)

func tryAuth(user *ipa.UserRecord, answer *model.SecurityAnswer, password, challenge, code string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("Please provide a password")
	}
	if user.OTPOnly() && len(code) == 0 {
		return "", errors.New("Please provide a six-digit authentication code")
	}
	if user.OTPOnly() {
		password += code
	} else if viper.GetBool("force_2fa") && answer != nil && !answer.Verify(challenge) {
		return "", errors.New("The security answer you provided does not match. Please check that you are entering the correct answer.")
	}

	c := app.NewIpaClient(true)

	sess, err := c.Login(string(user.Uid), password)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":              string(user.Uid),
			"ipa_client_error": err,
		}).Error("tryauth: failed login attempt")
		return "", errors.New("Invalid login")
	}

	return sess, nil
}

func checkUser(uid string) (*ipa.UserRecord, error) {
	if len(uid) == 0 {
		return nil, errors.New("Please provide a username")
	}

	c := app.NewIpaClient(true)

	userRec, err := c.UserShow(uid)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":              uid,
			"ipa_client_error": err,
		}).Error("failed to check user")
		return nil, errors.New("Invalid login")
	}

	return userRec, nil
}

func LoginHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		message := ""
		session, err := ctx.GetSession(r)
		if err != nil {
			logout(ctx, w, r)
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		if r.Method == "POST" {
			uid := r.FormValue("uid")

			_, err = checkUser(uid)
			if err != nil {
				message = err.Error()
			} else {
				session.Values[app.CookieKeyUser] = uid
				err := session.Save(r, w)
				if err != nil {
					log.WithFields(log.Fields{
						"user":  uid,
						"error": err.Error(),
					}).Error("loginhandler: failed to save session")
					logout(ctx, w, r)
					ctx.RenderError(w, http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/auth/2fa", 302)
				return
			}
		}

		vars := map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"message":        message}

		ctx.RenderTemplate(w, "login.html", vars)
	})
}

func TwoFactorAuthHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := ctx.GetSession(r)
		if err != nil {
			logout(ctx, w, r)
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		uid := session.Values[app.CookieKeyUser]
		user, err := checkUser(uid.(string))
		if err != nil {
			logout(ctx, w, r)
			http.Redirect(w, r, "/auth/login", 302)
			return
		}

		checkAuth(ctx, session, user, w, r)
	})
}

func checkAuth(ctx *app.AppContext, session *sessions.Session, user *ipa.UserRecord, w http.ResponseWriter, r *http.Request) {
	answer, err := model.FetchAnswer(ctx.DB, string(user.Uid))
	if err != nil && err != sql.ErrNoRows {
		log.WithFields(log.Fields{
			"uid":   string(user.Uid),
			"error": err,
		}).Error("Failed to fetch security question")
		logout(ctx, w, r)
		http.Redirect(w, r, "/auth/login", 302)
		return
	}

	message := ""

	if r.Method == "POST" {
		sid, err := tryAuth(user, answer, r.FormValue("password"), r.FormValue("answer"), r.FormValue("code"))
		if err != nil {
			message = err.Error()
		} else {
			session.Values[app.CookieKeySID] = sid
			if answer != nil {
				session.Values[app.CookieKeyAuthenticated] = true
			}
			err := session.Save(r, w)
			if err != nil {
				log.WithFields(log.Fields{
					"user":  string(user.Uid),
					"error": err.Error(),
				}).Error("failed to save session")
				logout(ctx, w, r)
				ctx.RenderError(w, http.StatusInternalServerError)
				return
			}

			if answer != nil {
				http.Redirect(w, r, "/", 302)
			} else {
				http.Redirect(w, r, "/auth/setsec", 302)
			}
			return
		}
	}

	vars := map[string]interface{}{
		csrf.TemplateTag:   csrf.TemplateField(r),
		"answer":           answer,
		"otpRequired":      user.OTPOnly(),
		"questionRequired": viper.GetBool("force_2fa"),
		"message":          message}

	ctx.RenderTemplate(w, "login-2fa.html", vars)
}

func logout(ctx *app.AppContext, w http.ResponseWriter, r *http.Request) {
	session, err := ctx.GetSession(r)
	if err != nil {
		ctx.RenderError(w, http.StatusInternalServerError)
		return
	}
	delete(session.Values, app.CookieKeySID)
	delete(session.Values, app.CookieKeyUser)
	delete(session.Values, app.CookieKeyAuthenticated)
	session.Options.MaxAge = -1

	err = session.Save(r, w)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("logouthandler: failed to save session")
		ctx.RenderError(w, http.StatusInternalServerError)
		return
	}
}

func LogoutHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logout(ctx, w, r)
		http.Redirect(w, r, "/auth/login", 302)
	})
}

func IndexHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ctx.GetUser(r)
		if user == nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		vars := map[string]interface{}{
			"user": user}

		ctx.RenderTemplate(w, "index.html", vars)
	})
}
