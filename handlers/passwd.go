// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"unicode/utf8"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/justinas/nosurf"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/model"
	"golang.org/x/crypto/bcrypt"
)

func setupAccount(ctx *app.AppContext, questions []*model.SecurityQuestion, token *model.Token, r *http.Request) error {
	pass := r.FormValue("password")
	pass2 := r.FormValue("password2")

	if len(pass) < viper.GetInt("min_passwd_len") || len(pass2) < viper.GetInt("min_passwd_len") {
		return errors.New(fmt.Sprintf("Please set a password at least %d characters in length.", viper.GetInt("min_passwd_len")))
	}

	if pass != pass2 {
		return errors.New("Password do not match. Please confirm your password.")
	}

	err := updateSecurityQuestion(ctx, questions, token.UserName, r)
	if err != nil {
		return err
	}

	// Setup password in FreeIPA
	err = setPassword(token.UserName, "", pass)
	if err != nil {
		if ierr, ok := err.(*ipa.ErrPasswordPolicy); ok {
			log.WithFields(log.Fields{
				"uid":   token.UserName,
				"error": ierr.Error(),
			}).Error("password does not conform to policy")
			return errors.New("Your password is too weak. Please ensure your password includes a number and lower/upper case character")
		}

		if ierr, ok := err.(*ipa.ErrInvalidPassword); ok {
			log.WithFields(log.Fields{
				"uid":   token.UserName,
				"error": ierr.Error(),
			}).Error("invalid password from FreeIPA")
			return errors.New("Invalid password.")
		}

		log.WithFields(log.Fields{
			"uid":   token.UserName,
			"error": err.Error(),
		}).Error("failed to set user password in FreeIPA")
		return errors.New("Fatal system error")
	}

	// Destroy token
	err = model.DestroyToken(ctx.Db, token.Token)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   token.UserName,
			"error": err.Error(),
		}).Error("failed to remove token from database")
		return errors.New("Fatal system error")
	}

	return nil
}

func SetupAccountHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tk, ok := model.VerifyToken(app.AccountSetupSalt, mux.Vars(r)["token"])
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			ctx.RenderNotFound(w)
			return
		}

		token, err := model.FetchToken(ctx.Db, tk, viper.GetInt("setup_max_age"))
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Error("Failed to fetch token from database")
			w.WriteHeader(http.StatusNotFound)
			ctx.RenderNotFound(w)
			return
		}

		if token.Attempts > viper.GetInt("max_attempts") {
			log.WithFields(log.Fields{
				"token": token.Token,
				"uid":   token.UserName,
			}).Error("Too many attempts for token.")
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
		completed := false

		if r.Method == "POST" {
			err := setupAccount(ctx, questions, token, r)
			if err != nil {
				message = err.Error()
				completed = false

				err := model.IncrementToken(ctx.Db, token.Token)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Error("Failed to increment token attempts")
				}
			} else {
				completed = true
				err = ctx.SendEmail(token.Email, fmt.Sprintf("[%s] Your account confirmation", viper.GetString("email_prefix")), "setup-account-confirm.txt", nil)
				if err != nil {
					log.WithFields(log.Fields{
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

		ctx.RenderTemplate(w, "setup-account.html", vars)
	})
}

func resetPassword(ctx *app.AppContext, answer *model.SecurityAnswer, token *model.Token, r *http.Request) error {
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
			log.WithFields(log.Fields{
				"uid":   token.UserName,
				"error": ierr.Error(),
			}).Error("password does not conform to policy")
			return errors.New("Your password is too weak. Please ensure your password includes a number and lower/upper case character")
		}

		if ierr, ok := err.(*ipa.ErrInvalidPassword); ok {
			log.WithFields(log.Fields{
				"uid":   token.UserName,
				"error": ierr.Error(),
			}).Error("invalid password from FreeIPA")
			return errors.New("Invalid password.")
		}

		log.WithFields(log.Fields{
			"uid":   token.UserName,
			"error": err.Error(),
		}).Error("failed to set user password in FreeIPA")
		return errors.New("Fatal system error")
	}

	// Destroy token
	err = model.DestroyToken(ctx.Db, token.Token)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   token.UserName,
			"error": err.Error(),
		}).Error("failed to remove token from database")
		return errors.New("Fatal system error")
	}

	return nil
}

func ResetPasswordHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tk, ok := model.VerifyToken(app.ResetSalt, mux.Vars(r)["token"])
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			ctx.RenderNotFound(w)
			return
		}

		token, err := model.FetchToken(ctx.Db, tk, viper.GetInt("reset_max_age"))
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Error("Failed to fetch token from database")
			w.WriteHeader(http.StatusNotFound)
			ctx.RenderNotFound(w)
			return
		}

		if token.Attempts > viper.GetInt("max_attempts") {
			log.WithFields(log.Fields{
				"token": token.Token,
				"uid":   token.UserName,
			}).Error("Too many attempts for token.")
			w.WriteHeader(http.StatusNotFound)
			ctx.RenderNotFound(w)
			return
		}

		answer, err := model.FetchAnswer(ctx.Db, token.UserName)
		if err != nil {
			log.WithFields(log.Fields{
				"uid":   token.UserName,
				"error": err,
			}).Error("Failed to fetch security answer")
			w.WriteHeader(http.StatusNotFound)
			ctx.RenderNotFound(w)
			return
		}

		message := ""
		completed := false

		if r.Method == "POST" {
			err := resetPassword(ctx, answer, token, r)
			if err != nil {
				message = err.Error()
				completed = false

				err := model.IncrementToken(ctx.Db, token.Token)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Error("Failed to increment token attempts")
				}
			} else {
				completed = true
				err = ctx.SendEmail(token.Email, fmt.Sprintf("[%s] Your password change confirmation", viper.GetString("email_prefix")), "reset-password-confirm.txt", nil)
				if err != nil {
					log.WithFields(log.Fields{
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

		ctx.RenderTemplate(w, "reset-password.html", vars)
	})
}

func forgotPassword(ctx *app.AppContext, r *http.Request) error {
	uid := r.FormValue("uid")
	if len(uid) == 0 {
		return errors.New("Please provide a user name.")
	}

	_, err := model.FetchTokenByUser(ctx.Db, uid, viper.GetInt("setup_max_age"))
	if err == nil {
		log.WithFields(log.Fields{
			"uid": uid,
		}).Error("Forgotpw: user already has active token")
		return nil
	}

	client := app.NewIpaClient(true)
	userRec, err := client.UserShow(uid)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Forgotpw: invalid uid")
		return nil
	}

	if len(userRec.Email) == 0 {
		log.WithFields(log.Fields{
			"uid": uid,
		}).Error("Forgotpw: missing email address")
		return nil
	}

	_, err = model.FetchAnswer(ctx.Db, uid)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Forgotpw: Failed to fetch security answer")
		return nil
	}

	token, err := model.NewToken(ctx.Db, uid, string(userRec.Email))
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Forgotpw: Failed to create token")
		return nil
	}

	vars := map[string]interface{}{
		"link": fmt.Sprintf("%s/auth/resetpw/%s", viper.GetString("email_link_base"), model.SignToken(app.ResetSalt, token.Token))}

	err = ctx.SendEmail(token.Email, fmt.Sprintf("[%s] Please reset your password", viper.GetString("email_prefix")), "reset-password.txt", vars)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Forgotpw: failed send email to user")
	}

	return nil
}

func ForgotPasswordHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		message := ""
		completed := false

		if r.Method == "POST" {
			err := forgotPassword(ctx, r)
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

		ctx.RenderTemplate(w, "forgot-password.html", vars)
	})
}

func setPassword(uid, oldPass, newPass string) error {
	c := app.NewIpaClient(true)

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

func changePassword(ctx *app.AppContext, user *ipa.UserRecord, r *http.Request) error {
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
			log.WithFields(log.Fields{
				"uid":   user.Uid,
				"error": ierr.Error(),
			}).Error("password does not conform to policy")
			return errors.New("Password policy error. Your password is either too weak or you just changed your password within the last hour. Please ensure your password includes a number and lower/upper case character. You can only update your password once an hour.")
		}

		if ierr, ok := err.(*ipa.ErrInvalidPassword); ok {
			log.WithFields(log.Fields{
				"uid":   user.Uid,
				"error": ierr.Error(),
			}).Error("invalid password from FreeIPA")
			return errors.New("Invalid password.")
		}

		log.WithFields(log.Fields{
			"uid":   user.Uid,
			"error": err.Error(),
		}).Error("failed to set user password in FreeIPA")
		return errors.New("Fatal system error")
	}

	return nil
}

func ChangePasswordHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ctx.GetUser(r)
		if user == nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		message := ""
		completed := false

		if r.Method == "POST" {
			err := changePassword(ctx, user, r)
			if err != nil {
				message = err.Error()
				completed = false
			} else {
				completed = true
				if len(user.Email) > 0 {
					err = ctx.SendEmail(string(user.Email), fmt.Sprintf("[%s] Your password change confirmation", viper.GetString("email_prefix")), "reset-password-confirm.txt", nil)
					if err != nil {
						log.WithFields(log.Fields{
							"uid":   user.Uid,
							"error": err,
						}).Error("failed to send reset confirmation email to user")
					}
				} else {
					log.WithFields(log.Fields{
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

		ctx.RenderTemplate(w, "change-password.html", vars)
	})
}
