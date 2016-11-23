// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"unicode/utf8"

	log "github.com/Sirupsen/logrus"
	"github.com/justinas/nosurf"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/model"
	"golang.org/x/crypto/bcrypt"
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
		if sq.Id == q {
			found = true
			break
		}
	}

	if found == false {
		return errors.New("Invalid security question")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(answer), bcrypt.DefaultCost)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   userName,
			"error": err.Error(),
		}).Error("failed to generate bcrypt hash of answer")
		return errors.New("Fatal system error")
	}

	a := &model.SecurityAnswer{
		UserName:   userName,
		QuestionId: q,
		Answer:     string(hash)}

	err = model.StoreAnswer(ctx.Db, a)
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

		questions, err := model.FetchQuestions(ctx.Db)
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
			"token":     nosurf.Token(r),
			"completed": completed,
			"user":      user,
			"questions": questions,
			"message":   message}

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

		_, err = model.FetchAnswer(ctx.Db, string(user.Uid))
		if err == nil {
			log.WithFields(log.Fields{
				"uid":   string(user.Uid),
				"error": err,
			}).Error("User already has security question set.")
			w.WriteHeader(http.StatusNotFound)
			ctx.RenderNotFound(w)
			return
		}

		questions, err := model.FetchQuestions(ctx.Db)
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
				session.Values[app.CookieKeyQuestion] = "true"
				err = session.Save(r, w)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Error("login question handler: failed to save session")
					ctx.RenderError(w, http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/", 302)
				return
			}
		}

		vars := map[string]interface{}{
			"token":     nosurf.Token(r),
			"questions": questions,
			"message":   message}

		ctx.RenderTemplate(w, "setup-question.html", vars)
	})
}
