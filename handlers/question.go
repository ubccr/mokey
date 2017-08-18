// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/gorilla/csrf"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/model"
)

func updateSecurityQuestion(ctx *app.AppContext, questions []*model.SecurityQuestion, userName string, r *http.Request) error {
	qid := r.FormValue("qid")
	answer := r.FormValue("answer")

	if len(qid) == 0 || len(answer) == 0 {
		return errors.New("Please choose a security question and answer.")
	}

	if utf8.RuneCountInString(answer) < 2 || utf8.RuneCountInString(answer) > 100 {
		return errors.New("Invalid answer. Must be between 2 and 100 characters long.")
	}

	q, err := strconv.Atoi(qid)
	if err != nil {
		return errors.New("Invalid security question")
	}

	found := false
	for _, sq := range questions {
		if sq.ID == q {
			found = true
			break
		}
	}

	if found == false {
		return errors.New("Invalid security question")
	}

	err = model.StoreAnswer(ctx.DB, userName, answer, q)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   userName,
			"error": err.Error(),
		}).Error("failed to save answer to the database")
		return errors.New("Fatal system error")
	}

	return nil
}

func UpdateSecurityQuestionHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ctx.GetUser(r)
		if user == nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		questions, err := model.FetchQuestions(ctx.DB)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Error("Failed to fetch questions from database")
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		message := ""
		completed := false

		if r.Method == "POST" {
			err := updateSecurityQuestion(ctx, questions, string(user.Uid), r)
			if err != nil {
				message = err.Error()
				completed = false
			} else {
				completed = true
			}
		}

		vars := map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"completed":      completed,
			"user":           user,
			"questions":      questions,
			"message":        message}

		ctx.RenderTemplate(w, "update-security-question.html", vars)
	})
}

func SetupQuestionHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := ctx.GetSession(r)
		if err != nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		user := ctx.GetUser(r)
		if user == nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		_, err = model.FetchAnswer(ctx.DB, string(user.Uid))
		if err == nil {
			log.WithFields(log.Fields{
				"uid":   string(user.Uid),
				"error": err,
			}).Error("User already has security question set.")
			w.WriteHeader(http.StatusNotFound)
			ctx.RenderNotFound(w)
			return
		}

		questions, err := model.FetchQuestions(ctx.DB)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Error("Failed to fetch questions from database")
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		message := ""

		if r.Method == "POST" {
			err := updateSecurityQuestion(ctx, questions, string(user.Uid), r)
			if err != nil {
				message = err.Error()
			} else {
				session.Values[app.CookieKeyAuthenticated] = true
				err = session.Save(r, w)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Error("login question handler: failed to save session")
					ctx.RenderError(w, http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, ctx.GetWYAF(session), 302)
				delete(session.Values, app.CookieKeyWYAF)
				session.Save(r, w)
				return
			}
		}

		vars := map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"questions":      questions,
			"message":        message}

		ctx.RenderTemplate(w, "setup-question.html", vars)
	})
}
