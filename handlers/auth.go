// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"errors"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/justinas/nosurf"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/model"
	"golang.org/x/crypto/bcrypt"
)

func tryAuth(uid, pass string) (string, *ipa.UserRecord, error) {
	if len(uid) == 0 || len(pass) == 0 {
		return "", nil, errors.New("Please provide a uid/password")
	}

	c := app.NewIpaClient(true)

	sess, err := c.Login(uid, pass)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":              uid,
			"ipa_client_error": err,
		}).Error("tryauth: failed login attempt")
		return "", nil, errors.New("Invalid login")
	}

	userRec, err := c.UserShow(uid)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":              uid,
			"ipa_client_error": err,
		}).Error("tryauth: failed to fetch user info")
		return "", nil, errors.New("Invalid login")
	}

	return sess, userRec, nil
}

func LoginHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		message := ""
		session, err := ctx.GetSession(r)
		if err != nil {
			ctx.ErrorHandler(w, http.StatusInternalServerError)
			return
		}

		if r.Method == "POST" {
			uid := r.FormValue("uid")
			pass := r.FormValue("password")

			sid, userRec, err := tryAuth(uid, pass)
			if err != nil {
				message = err.Error()
			} else {
				session.Values[app.CookieKeySID] = sid
				session.Values[app.CookieKeyUser] = userRec
				err = session.Save(r, w)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Error("loginhandler: failed to save session")
					ctx.ErrorHandler(w, http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/auth/question", 302)
				return
			}
		}

		vars := map[string]interface{}{
			"token":   nosurf.Token(r),
			"message": message}

		ctx.RenderTemplate(w, "login.html", vars)
	})
}

func LoginQuestionHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := ctx.GetSession(r)
		if err != nil {
			ctx.ErrorHandler(w, http.StatusInternalServerError)
			return
		}

		user := ctx.GetUser(r)
		if user == nil {
			ctx.ErrorHandler(w, http.StatusInternalServerError)
			return
		}

		answer, err := model.FetchAnswer(ctx.Db, string(user.Uid))
		if err != nil {
			log.WithFields(log.Fields{
				"uid":   string(user.Uid),
				"error": err,
			}).Error("User can't login. No security answer has been set")
			http.Redirect(w, r, "/auth/setsec", 302)
			return
		}

		message := ""

		if r.Method == "POST" {
			ans := r.FormValue("answer")
			err := bcrypt.CompareHashAndPassword([]byte(answer.Answer), []byte(ans))
			if err != nil {
				message = "The security answer you provided does not match. Please check that you are entering the correct answer."
			} else {
				session.Values[app.CookieKeyQuestion] = "true"
				err = session.Save(r, w)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Error("login question handler: failed to save session")
					ctx.ErrorHandler(w, http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/", 302)
				return
			}
		}

		vars := map[string]interface{}{
			"token":    nosurf.Token(r),
			"question": answer.Question,
			"message":  message}

		ctx.RenderTemplate(w, "login-question.html", vars)
	})
}

func logout(ctx *app.AppContext, w http.ResponseWriter, r *http.Request) {
	session, err := ctx.GetSession(r)
	if err != nil {
		ctx.ErrorHandler(w, http.StatusInternalServerError)
		return
	}
	delete(session.Values, app.CookieKeySID)
	delete(session.Values, app.CookieKeyUser)
	delete(session.Values, app.CookieKeyQuestion)
	session.Options.MaxAge = -1

	err = session.Save(r, w)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("logouthandler: failed to save session")
		ctx.ErrorHandler(w, http.StatusInternalServerError)
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
			ctx.ErrorHandler(w, http.StatusInternalServerError)
			return
		}

		vars := map[string]interface{}{
			"user": user}

		ctx.RenderTemplate(w, "index.html", vars)
	})
}
