package server

import (
	"errors"
	"net/http"
	"path"

	"github.com/dchest/captcha"
	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
	"github.com/ubccr/mokey/util"
)

func (h *Handler) SetupAccount(c echo.Context) error {
	_, tk := path.Split(c.Request().URL.Path)
	token, err := h.verifyToken(tk, util.VerifySalt, viper.GetInt("setup_max_age"))
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"token": tk,
		}).Error("Invalid token found")
		return echo.NewHTTPError(http.StatusNotFound, "Invalid token")
	}

	userRec, err := h.client.UserShow(token.UserName)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   token.UserName,
			"error": err,
		}).Error("Failed to fetch user record from freeipa")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}

	vars := map[string]interface{}{
		"uid":   string(userRec.Uid),
		"email": string(userRec.Email),
		"csrf":  c.Get("csrf").(string),
	}

	if c.Request().Method == "POST" {
		if userRec.Locked() {
			// Enable user account
			err := h.client.UserEnable(token.UserName)
			if err != nil {
				log.WithFields(log.Fields{
					"uid":   token.UserName,
					"error": err,
				}).Error("Failed enable user in FreeIPA")
				return echo.NewHTTPError(http.StatusInternalServerError, "Failed to enable user")
			}
		}

		// Destroy token
		err = h.db.DestroyToken(token.Token)
		if err != nil {
			log.WithFields(log.Fields{
				"uid":   token.UserName,
				"error": err,
			}).Error("Failed to remove token from database")
		}

		vars["completed"] = true
	}

	return c.Render(http.StatusOK, "setup-account.html", vars)
}

func (h *Handler) ForgotPassword(c echo.Context) error {
	vars := map[string]interface{}{
		"csrf": c.Get("csrf").(string),
	}

	if viper.GetBool("enable_captcha") {
		vars["captchaID"] = captcha.New()
	}

	if c.Request().Method == "POST" {
		uid := c.FormValue("uid")
		captchaID := c.FormValue("captcha_id")
		captchaSol := c.FormValue("captcha_sol")

		err := h.sendPasswordReset(uid, captchaID, captchaSol)
		if err != nil {
			vars["message"] = err.Error()
		} else {
			vars["completed"] = true
		}
	}

	return c.Render(http.StatusOK, "forgot-password.html", vars)
}

func (h *Handler) ResetPassword(c echo.Context) error {
	_, tk := path.Split(c.Request().URL.Path)
	token, err := h.verifyToken(tk, util.ResetSalt, viper.GetInt("setup_max_age"))
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"token": tk,
		}).Error("Invalid token found")
		return echo.NewHTTPError(http.StatusNotFound, "Invalid token")
	}

	userRec, err := h.client.UserShow(token.UserName)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   token.UserName,
			"error": err,
		}).Error("Failed to fetch user record from freeipa")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}

	vars := map[string]interface{}{
		"uid":         string(userRec.Uid),
		"otpRequired": userRec.OTPOnly(),
		"csrf":        c.Get("csrf").(string),
	}

	if c.Request().Method == "POST" {
		pass := c.FormValue("password")
		pass2 := c.FormValue("password2")
		challenge := c.FormValue("challenge")

		err := h.resetPassword(userRec, pass, pass2, challenge)
		if err != nil {
			vars["message"] = err.Error()

			err := h.db.IncrementToken(token.Token)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err.Error(),
				}).Error("Failed to increment token attempts")
			}
		} else {
			vars["success"] = true

			// Destroy token
			err := h.db.DestroyToken(token.Token)
			if err != nil {
				log.WithFields(log.Fields{
					"uid":   token.UserName,
					"error": err.Error(),
				}).Error("failed to remove token from database")
			}
		}
	}

	return c.Render(http.StatusOK, "reset-password.html", vars)
}

func (h *Handler) resetPassword(user *ipa.UserRecord, pass, pass2, challenge string) error {
	if err := util.CheckPassword(pass, viper.GetInt("min_passwd_len"), viper.GetInt("min_passwd_classes")); err != nil {
		return err
	}

	if pass != pass2 {
		return errors.New("Password do not match. Please confirm your password.")
	}

	if user.OTPOnly() && len(challenge) == 0 {
		return errors.New("Please provide a six-digit authentication code")
	}

	if !user.OTPOnly() {
		challenge = ""
	}

	// Reset password in FreeIPA
	rand, err := h.client.ResetPassword(string(user.Uid))
	if err != nil {
		return err
	}

	// Set new password in FreeIPA
	err = h.client.SetPassword(string(user.Uid), rand, pass, challenge)
	if err != nil {
		if ierr, ok := err.(*ipa.ErrPasswordPolicy); ok {
			log.WithFields(log.Fields{
				"uid":   string(user.Uid),
				"error": ierr.Error(),
			}).Error("password does not conform to policy")
			return errors.New("Your password is too weak. Please ensure your password includes a number and lower/upper case character")
		}

		if ierr, ok := err.(*ipa.ErrInvalidPassword); ok {
			log.WithFields(log.Fields{
				"uid":   string(user.Uid),
				"error": ierr.Error(),
			}).Error("invalid password from FreeIPA")
			return errors.New("Invalid OTP code.")
		}

		log.WithFields(log.Fields{
			"uid":   string(user.Uid),
			"error": err.Error(),
		}).Error("failed to set user password in FreeIPA")
		return errors.New("Fatal system error")
	}

	return nil
}

func (h *Handler) sendPasswordReset(uid, captchaID, captchaSol string) error {
	if len(uid) == 0 {
		return errors.New("Please provide a username")
	}

	if viper.GetBool("enable_captcha") {
		if len(captchaID) == 0 {
			return errors.New("Invalid captcha provided")
		}
		if len(captchaSol) == 0 {
			return errors.New("Please type in the numbers you see in the picture")
		}

		if !captcha.VerifyString(captchaID, captchaSol) {
			return errors.New("The numbers you typed in do not match the image")
		}
	}

	_, err := h.db.FetchTokenByUser(uid, viper.GetInt("setup_max_age"))
	if err == nil {
		log.WithFields(log.Fields{
			"uid": uid,
		}).Error("Forgotpw: user already has active token")
		return nil
	}

	userRec, err := h.client.UserShow(uid)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Forgotpw: invalid uid")
		return errors.New("Invalid username")
	}

	if len(userRec.Email) == 0 {
		log.WithFields(log.Fields{
			"uid": uid,
		}).Error("Forgotpw: missing email address")
		return errors.New("No email address provided for that username")
	}

	err = h.emailer.SendResetPasswordEmail(uid, string(userRec.Email))
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Forgotpw: failed send email to user")
	}

	return nil
}

func (h *Handler) verifyToken(rawToken, salt string, maxAge int) (*model.Token, error) {
	tk, ok := h.db.VerifyToken(salt, rawToken)
	if !ok {
		return nil, errors.New("Invalid token")
	}

	token, err := h.db.FetchToken(tk, maxAge)
	if err != nil {
		return nil, err
	}

	if token.Attempts > viper.GetInt("max_attempts") {
		log.WithFields(log.Fields{
			"token": token.Token,
			"uid":   token.UserName,
		}).Error("Too many attempts for token.")
		return nil, err
	}

	return token, nil
}
