// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/justinas/nosurf"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
	"golang.org/x/crypto/bcrypt"
)

func renderTemplate(w http.ResponseWriter, t *template.Template, data interface{}) {
	var buf bytes.Buffer
	err := t.ExecuteTemplate(&buf, "layout", data)

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("failed to render template")
		http.Error(w, "Fatal error rendering template", http.StatusInternalServerError)
		return
	}

	buf.WriteTo(w)
}

func errorHandler(app *Application, w http.ResponseWriter, status int) {
	w.WriteHeader(status)

	renderTemplate(w, app.templates["error.html"], nil)
}

func setupAccount(app *Application, questions []*model.SecurityQuestion, token *model.Token, r *http.Request) error {
	pass := r.FormValue("password")
	pass2 := r.FormValue("password2")

	if len(pass) < viper.GetInt("min_passwd_len") || len(pass2) < viper.GetInt("min_passwd_len") {
		return errors.New(fmt.Sprintf("Please set a password at least %d characters in length.", viper.GetInt("min_passwd_len")))
	}

	if pass != pass2 {
		return errors.New("Password do not match. Please confirm your password.")
	}

	err := updateSecurityQuestion(app, questions, token.UserName, r)
	if err != nil {
		return err
	}

	// Setup password in FreeIPA
	err = setPassword(token.UserName, "", pass)
	if err != nil {
		if ierr, ok := err.(*ipa.ErrPasswordPolicy); ok {
			logrus.WithFields(logrus.Fields{
				"uid":   token.UserName,
				"error": ierr.Error(),
			}).Error("password does not conform to policy")
			return errors.New("Your password is too weak. Please ensure your password includes a number and lower/upper case character")
		}

		if ierr, ok := err.(*ipa.ErrInvalidPassword); ok {
			logrus.WithFields(logrus.Fields{
				"uid":   token.UserName,
				"error": ierr.Error(),
			}).Error("invalid password from FreeIPA")
			return errors.New("Invalid password.")
		}

		logrus.WithFields(logrus.Fields{
			"uid":   token.UserName,
			"error": err.Error(),
		}).Error("failed to set user password in FreeIPA")
		return errors.New("Fatal system error")
	}

	// Destroy token
	err = model.DestroyToken(app.db, token.Token)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"uid":   token.UserName,
			"error": err.Error(),
		}).Error("failed to remove token from database")
		return errors.New("Fatal system error")
	}

	return nil
}

func SetupAccountHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tk, ok := model.VerifyToken(ACCOUNT_SETUP_SALT, mux.Vars(r)["token"])
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			renderTemplate(w, app.templates["404.html"], nil)
			return
		}

		token, err := model.FetchToken(app.db, tk, viper.GetInt("setup_max_age"))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("Failed to fetch token from database")
			w.WriteHeader(http.StatusNotFound)
			renderTemplate(w, app.templates["404.html"], nil)
			return
		}

		if token.Attempts > viper.GetInt("max_attempts") {
			logrus.WithFields(logrus.Fields{
				"token": token.Token,
				"uid":   token.UserName,
			}).Error("Too many attempts for token.")
			w.WriteHeader(http.StatusNotFound)
			renderTemplate(w, app.templates["404.html"], nil)
			return
		}

		questions, err := model.FetchQuestions(app.db)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("Failed to fetch questions from database")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		message := ""
		completed := false

		if r.Method == "POST" {
			err := setupAccount(app, questions, token, r)
			if err != nil {
				message = err.Error()
				completed = false

				err := model.IncrementToken(app.db, token.Token)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"error": err.Error(),
					}).Error("Failed to increment token attempts")
				}
			} else {
				completed = true
				err = app.SendEmail(token.Email, fmt.Sprintf("[%s] Your account confirmation", viper.GetString("email_prefix")), "setup-account-confirm.txt", nil)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"uid":   token.UserName,
						"error": err,
					}).Error("failed to send setup confirmation email to user")
				}
			}
		}

		vars := map[string]interface{}{
			"token":     nosurf.Token(r),
			"uid":       token.UserName,
			"completed": completed,
			"questions": questions,
			"message":   message}

		renderTemplate(w, app.templates["setup-account.html"], vars)
	})
}

func resetPassword(app *Application, answer *model.SecurityAnswer, token *model.Token, r *http.Request) error {
	ans := r.FormValue("answer")
	pass := r.FormValue("password")
	pass2 := r.FormValue("password2")

	if len(pass) < viper.GetInt("min_passwd_len") || len(pass2) < viper.GetInt("min_passwd_len") {
		return errors.New(fmt.Sprintf("Please set a password at least %d characters in length.", viper.GetInt("min_passwd_len")))
	}

	if pass != pass2 {
		return errors.New("Password do not match. Please confirm your password.")
	}

	if utf8.RuneCountInString(ans) < 2 || utf8.RuneCountInString(ans) > 100 {
		return errors.New("Invalid answer. Must be between 2 and 100 characters long.")
	}

	err := bcrypt.CompareHashAndPassword([]byte(answer.Answer), []byte(ans))
	if err != nil {
		return errors.New("The security answer you provided does not match. Please check that you are entering the correct answer.")
	}

	// Setup password in FreeIPA
	err = setPassword(token.UserName, "", pass)
	if err != nil {
		if ierr, ok := err.(*ipa.ErrPasswordPolicy); ok {
			logrus.WithFields(logrus.Fields{
				"uid":   token.UserName,
				"error": ierr.Error(),
			}).Error("password does not conform to policy")
			return errors.New("Your password is too weak. Please ensure your password includes a number and lower/upper case character")
		}

		if ierr, ok := err.(*ipa.ErrInvalidPassword); ok {
			logrus.WithFields(logrus.Fields{
				"uid":   token.UserName,
				"error": ierr.Error(),
			}).Error("invalid password from FreeIPA")
			return errors.New("Invalid password.")
		}

		logrus.WithFields(logrus.Fields{
			"uid":   token.UserName,
			"error": err.Error(),
		}).Error("failed to set user password in FreeIPA")
		return errors.New("Fatal system error")
	}

	// Destroy token
	err = model.DestroyToken(app.db, token.Token)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"uid":   token.UserName,
			"error": err.Error(),
		}).Error("failed to remove token from database")
		return errors.New("Fatal system error")
	}

	return nil
}

func ResetPasswordHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tk, ok := model.VerifyToken(RESET_SALT, mux.Vars(r)["token"])
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			renderTemplate(w, app.templates["404.html"], nil)
			return
		}

		token, err := model.FetchToken(app.db, tk, viper.GetInt("reset_max_age"))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("Failed to fetch token from database")
			w.WriteHeader(http.StatusNotFound)
			renderTemplate(w, app.templates["404.html"], nil)
			return
		}

		if token.Attempts > viper.GetInt("max_attempts") {
			logrus.WithFields(logrus.Fields{
				"token": token.Token,
				"uid":   token.UserName,
			}).Error("Too many attempts for token.")
			w.WriteHeader(http.StatusNotFound)
			renderTemplate(w, app.templates["404.html"], nil)
			return
		}

		answer, err := model.FetchAnswer(app.db, token.UserName)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"uid":   token.UserName,
				"error": err,
			}).Error("Failed to fetch security answer")
			w.WriteHeader(http.StatusNotFound)
			renderTemplate(w, app.templates["404.html"], nil)
			return
		}

		message := ""
		completed := false

		if r.Method == "POST" {
			err := resetPassword(app, answer, token, r)
			if err != nil {
				message = err.Error()
				completed = false

				err := model.IncrementToken(app.db, token.Token)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"error": err.Error(),
					}).Error("Failed to increment token attempts")
				}
			} else {
				completed = true
				err = app.SendEmail(token.Email, fmt.Sprintf("[%s] Your password change confirmation", viper.GetString("email_prefix")), "reset-password-confirm.txt", nil)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"uid":   token.UserName,
						"error": err,
					}).Error("failed to send reset confirmation email to user")
				}
			}
		}

		vars := map[string]interface{}{
			"token":     nosurf.Token(r),
			"uid":       token.UserName,
			"completed": completed,
			"question":  answer.Question,
			"message":   message}

		renderTemplate(w, app.templates["reset-password.html"], vars)
	})
}

func forgotPassword(app *Application, r *http.Request) error {
	uid := r.FormValue("uid")
	if len(uid) == 0 {
		return errors.New("Please provide a user name.")
	}

	_, err := model.FetchTokenByUser(app.db, uid, viper.GetInt("setup_max_age"))
	if err == nil {
		logrus.WithFields(logrus.Fields{
			"uid": uid,
		}).Error("Forgotpw: user already has active token")
		return nil
	}

	client := NewIpaClient(true)
	userRec, err := client.UserShow(uid)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Forgotpw: invalid uid")
		return nil
	}

	if len(userRec.Email) == 0 {
		logrus.WithFields(logrus.Fields{
			"uid": uid,
		}).Error("Forgotpw: missing email address")
		return nil
	}

	_, err = model.FetchAnswer(app.db, uid)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Forgotpw: Failed to fetch security answer")
		return nil
	}

	token, err := model.NewToken(app.db, uid, string(userRec.Email))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Forgotpw: Failed to create token")
		return nil
	}

	vars := map[string]interface{}{
		"link": fmt.Sprintf("%s/auth/resetpw/%s", viper.GetString("email_link_base"), model.SignToken(RESET_SALT, token.Token))}

	err = app.SendEmail(token.Email, fmt.Sprintf("[%s] Please reset your password", viper.GetString("email_prefix")), "reset-password.txt", vars)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Forgotpw: failed send email to user")
	}

	return nil
}

func ForgotPasswordHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		message := ""
		completed := false

		if r.Method == "POST" {
			err := forgotPassword(app, r)
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
			"message":   message}

		renderTemplate(w, app.templates["forgot-password.html"], vars)
	})
}

func setPassword(uid, oldPass, newPass string) error {
	c := NewIpaClient(true)

	if len(oldPass) == 0 {
		rand, err := c.ResetPassword(uid)
		if err != nil {
			return err
		}
		oldPass = rand
	}

	err := c.ChangePassword(uid, oldPass, newPass)
	if err != nil {
		return err
	}

	return nil
}

func tryAuth(uid, pass string) (string, *ipa.UserRecord, error) {
	if len(uid) == 0 || len(pass) == 0 {
		return "", nil, errors.New("Please provide a uid/password")
	}

	c := NewIpaClient(true)

	sess, err := c.Login(uid, pass)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"uid":              uid,
			"ipa_client_error": err,
		}).Error("tryauth: failed login attempt")
		return "", nil, errors.New("Invalid login")
	}

	userRec, err := c.UserShow(uid)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"uid":              uid,
			"ipa_client_error": err,
		}).Error("tryauth: failed to fetch user info")
		return "", nil, errors.New("Invalid login")
	}

	return sess, userRec, nil
}

func LoginHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		message := ""
		session, err := app.cookieStore.Get(r, MOKEY_COOKIE_SESSION)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("loginhandler: failed to get session")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		if r.Method == "POST" {
			uid := r.FormValue("uid")
			pass := r.FormValue("password")

			sid, userRec, err := tryAuth(uid, pass)
			if err != nil {
				message = err.Error()
			} else {
				session.Values[MOKEY_COOKIE_SID] = sid
				session.Values[MOKEY_COOKIE_USER] = userRec
				err = session.Save(r, w)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"error": err.Error(),
					}).Error("loginhandler: failed to save session")
					errorHandler(app, w, http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/auth/question", 302)
				return
			}
		}

		vars := map[string]interface{}{
			"token":   nosurf.Token(r),
			"message": message}

		renderTemplate(w, app.templates["login.html"], vars)
	})
}

func LoginQuestionHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := app.cookieStore.Get(r, MOKEY_COOKIE_SESSION)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("loginquestionhandler: failed to get session")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		user := context.Get(r, "user").(*ipa.UserRecord)
		if user == nil {
			logrus.Error("login question handler: user not found in request context")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		answer, err := model.FetchAnswer(app.db, string(user.Uid))
		if err != nil {
			logrus.WithFields(logrus.Fields{
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
				session.Values[MOKEY_COOKIE_QUESTION] = "true"
				err = session.Save(r, w)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"error": err.Error(),
					}).Error("login question handler: failed to save session")
					errorHandler(app, w, http.StatusInternalServerError)
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

		renderTemplate(w, app.templates["login-question.html"], vars)
	})
}

func logout(app *Application, w http.ResponseWriter, r *http.Request) {
	session, err := app.cookieStore.Get(r, MOKEY_COOKIE_SESSION)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("logouthandler: failed to get session")
		errorHandler(app, w, http.StatusInternalServerError)
		return
	}
	delete(session.Values, MOKEY_COOKIE_SID)
	delete(session.Values, MOKEY_COOKIE_USER)
	delete(session.Values, MOKEY_COOKIE_QUESTION)
	session.Options.MaxAge = -1

	err = session.Save(r, w)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("logouthandler: failed to save session")
		errorHandler(app, w, http.StatusInternalServerError)
		return
	}
}

func LogoutHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logout(app, w, r)
		http.Redirect(w, r, "/auth/login", 302)
	})
}

func IndexHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := context.Get(r, "user").(*ipa.UserRecord)
		if user == nil {
			logrus.Error("index handler: user not found in request context")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		vars := map[string]interface{}{
			"user": user}

		renderTemplate(w, app.templates["index.html"], vars)
	})
}

func changePassword(app *Application, user *ipa.UserRecord, r *http.Request) error {
	current := r.FormValue("password")
	pass := r.FormValue("new_password")
	pass2 := r.FormValue("new_password2")

	if len(current) < viper.GetInt("min_passwd_len") || len(pass) < viper.GetInt("min_passwd_len") || len(pass2) < viper.GetInt("min_passwd_len") {
		return errors.New(fmt.Sprintf("Please set a password at least %d characters in length.", viper.GetInt("min_passwd_len")))
	}

	if pass != pass2 {
		return errors.New("Password do not match. Please confirm your password.")
	}

	if current == pass {
		return errors.New("Current password is the same as new password. Please set a different password.")
	}

	// Setup password in FreeIPA
	err := setPassword(string(user.Uid), current, pass)
	if err != nil {
		if ierr, ok := err.(*ipa.ErrPasswordPolicy); ok {
			logrus.WithFields(logrus.Fields{
				"uid":   user.Uid,
				"error": ierr.Error(),
			}).Error("password does not conform to policy")
			return errors.New("Password policy error. Your password is either too weak or you just changed your password within the last hour. Please ensure your password includes a number and lower/upper case character. You can only update your password once an hour.")
		}

		if ierr, ok := err.(*ipa.ErrInvalidPassword); ok {
			logrus.WithFields(logrus.Fields{
				"uid":   user.Uid,
				"error": ierr.Error(),
			}).Error("invalid password from FreeIPA")
			return errors.New("Invalid password.")
		}

		logrus.WithFields(logrus.Fields{
			"uid":   user.Uid,
			"error": err.Error(),
		}).Error("failed to set user password in FreeIPA")
		return errors.New("Fatal system error")
	}

	return nil
}

func ChangePasswordHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := context.Get(r, "user").(*ipa.UserRecord)
		if user == nil {
			logrus.Error("changepw handler: user not found in request context")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		message := ""
		completed := false

		if r.Method == "POST" {
			err := changePassword(app, user, r)
			if err != nil {
				message = err.Error()
				completed = false
			} else {
				completed = true
				if len(user.Email) > 0 {
					err = app.SendEmail(string(user.Email), fmt.Sprintf("[%s] Your password change confirmation", viper.GetString("email_prefix")), "reset-password-confirm.txt", nil)
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"uid":   user.Uid,
							"error": err,
						}).Error("failed to send reset confirmation email to user")
					}
				} else {
					logrus.WithFields(logrus.Fields{
						"uid": user.Uid,
					}).Error("changepw: user missing email address")
				}
			}
		}

		vars := map[string]interface{}{
			"token":     nosurf.Token(r),
			"completed": completed,
			"user":      user,
			"message":   message}

		renderTemplate(w, app.templates["change-password.html"], vars)
	})
}

func updateSecurityQuestion(app *Application, questions []*model.SecurityQuestion, userName string, r *http.Request) error {
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
		logrus.WithFields(logrus.Fields{
			"uid":   userName,
			"error": err.Error(),
		}).Error("failed to generate bcrypt hash of answer")
		return errors.New("Fatal system error")
	}

	a := &model.SecurityAnswer{
		UserName:   userName,
		QuestionId: q,
		Answer:     string(hash)}

	err = model.StoreAnswer(app.db, a)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"uid":   userName,
			"error": err.Error(),
		}).Error("failed to save answer to the database")
		return errors.New("Fatal system error")
	}

	return nil
}

func UpdateSecurityQuestionHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := context.Get(r, "user").(*ipa.UserRecord)
		if user == nil {
			logrus.Error("securityquestion handler: user not found in request context")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		questions, err := model.FetchQuestions(app.db)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("Failed to fetch questions from database")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		message := ""
		completed := false

		if r.Method == "POST" {
			err := updateSecurityQuestion(app, questions, string(user.Uid), r)
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

		renderTemplate(w, app.templates["update-security-question.html"], vars)
	})
}

func SetupQuestionHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := app.cookieStore.Get(r, MOKEY_COOKIE_SESSION)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("setupquestionhandler: failed to get session")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		user := context.Get(r, "user").(*ipa.UserRecord)
		if user == nil {
			logrus.Error("setup question handler: user not found in request context")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		_, err = model.FetchAnswer(app.db, string(user.Uid))
		if err == nil {
			logrus.WithFields(logrus.Fields{
				"uid":   string(user.Uid),
				"error": err,
			}).Error("User already has security question set.")
			w.WriteHeader(http.StatusNotFound)
			renderTemplate(w, app.templates["404.html"], nil)
			return
		}

		questions, err := model.FetchQuestions(app.db)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("Failed to fetch questions from database")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		message := ""

		if r.Method == "POST" {
			err := updateSecurityQuestion(app, questions, string(user.Uid), r)
			if err != nil {
				message = err.Error()
			} else {
				session.Values[MOKEY_COOKIE_QUESTION] = "true"
				err = session.Save(r, w)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"error": err.Error(),
					}).Error("login question handler: failed to save session")
					errorHandler(app, w, http.StatusInternalServerError)
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

		renderTemplate(w, app.templates["setup-question.html"], vars)
	})
}

func SSHPubKeyHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := context.Get(r, "user").(*ipa.UserRecord)
		if user == nil {
			logrus.Error("sshpubkey handler: user not found in request context")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		session, err := app.cookieStore.Get(r, MOKEY_COOKIE_SESSION)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("sshpubkeyhandler: failed to get session")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		vars := map[string]interface{}{
			"flashes": session.Flashes(),
			"user":    user}

		session.Save(r, w)
		renderTemplate(w, app.templates["ssh-pubkey.html"], vars)
	})
}

func RemoveSSHPubKeyHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := context.Get(r, "user").(*ipa.UserRecord)
		if user == nil {
			logrus.Error("removesshpubkey handler: user not found in request context")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		session, err := app.cookieStore.Get(r, MOKEY_COOKIE_SESSION)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("removesshpubkeyhandler: failed to get session")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		index, _ := strconv.Atoi(mux.Vars(r)["index"])
		if index < 0 || index > len(user.SSHPubKeys) {
			logrus.WithFields(logrus.Fields{
				"user":  string(user.Uid),
				"index": index,
			}).Error("Invalid ssh pub key index")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		pubKeys := make([]string, len(user.SSHPubKeys))
		copy(pubKeys, user.SSHPubKeys)

		// Remove key at index
		pubKeys = append(pubKeys[:index], pubKeys[index+1:]...)

		sid := session.Values[MOKEY_COOKIE_SID]
		c := NewIpaClient(false)
		c.SetSession(sid.(string))

		newFps, err := c.UpdateSSHPubKeys(string(user.Uid), pubKeys)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"user":  string(user.Uid),
				"index": index,
				"error": err,
			}).Error("Failed to delete ssh pub key")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		user.SSHPubKeys = pubKeys
		user.SSHPubKeyFps = newFps
		session.Values[MOKEY_COOKIE_USER] = user
		session.AddFlash("SSH Pub Key Deleted")
		session.Save(r, w)

		http.Redirect(w, r, "/sshpubkey", 302)
		return
	})
}

func addSSHPubKey(user *ipa.UserRecord, pubKey, sid string) error {
	if len(pubKey) == 0 {
		return errors.New("No ssh key provided. Please provide a valid ssh public key")
	}

	pubKeys := make([]string, len(user.SSHPubKeys))
	copy(pubKeys, user.SSHPubKeys)
	found := false
	for _, k := range pubKeys {
		if k == pubKey {
			found = true
		}
	}

	if found {
		return errors.New("ssh key already exists.")
	}

	pubKeys = append(pubKeys, pubKey)

	c := NewIpaClient(false)
	c.SetSession(sid)

	newFps, err := c.UpdateSSHPubKeys(string(user.Uid), pubKeys)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			// Raised when a parameter value fails a validation rule
			if ierr.Code == 3009 {
				return errors.New("Invalid ssh public key")
			}
		} else {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
				"user":  string(user.Uid),
			}).Error("Ipa error when attempting to add new ssh public key")
			return errors.New("Fatal system error occured.")
		}
	}

	user.SSHPubKeys = pubKeys
	user.SSHPubKeyFps = newFps

	return nil
}

func NewSSHPubKeyHandler(app *Application) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := context.Get(r, "user").(*ipa.UserRecord)
		if user == nil {
			logrus.Error("newsshpubkey handler: user not found in request context")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		session, err := app.cookieStore.Get(r, MOKEY_COOKIE_SESSION)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("newsshpubkeyhandler: failed to get session")
			errorHandler(app, w, http.StatusInternalServerError)
			return
		}

		message := ""

		if r.Method == "POST" {
			err := r.ParseMultipartForm(4096)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"user": string(user.Uid),
					"err":  err,
				}).Error("Failed to parse multipart form")
				errorHandler(app, w, http.StatusInternalServerError)
				return
			}

			pubKey := ""

			files := r.MultipartForm.File["key_file"]
			if len(files) > 0 {
				// Only use first file
				file, err := files[0].Open()
				defer file.Close()
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"user": string(user.Uid),
						"err":  err,
					}).Error("Failed to open ssh pub key file upload")
					errorHandler(app, w, http.StatusInternalServerError)
					return
				}
				data, err := ioutil.ReadAll(file)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"user": string(user.Uid),
						"err":  err,
					}).Error("Failed to read ssh pub key file upload")
					errorHandler(app, w, http.StatusInternalServerError)
					return
				}
				pubKey = string(data)
			} else {
				pubKey = r.FormValue("key")
			}

			sid := session.Values[MOKEY_COOKIE_SID]
			err = addSSHPubKey(user, pubKey, sid.(string))

			if err == nil {
				session.Values[MOKEY_COOKIE_USER] = user
				session.AddFlash("SSH Public Key Added")
				session.Save(r, w)
				http.Redirect(w, r, "/sshpubkey", 302)
				return
			}

			message = err.Error()
		}

		vars := map[string]interface{}{
			"token":   nosurf.Token(r),
			"message": message,
			"user":    user}

		renderTemplate(w, app.templates["new-ssh-pubkey.html"], vars)
	})
}
