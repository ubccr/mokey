package server

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/util"
)

func (h *Handler) changePassword(client *ipa.Client, user *ipa.UserRecord, current, pass, pass2, challenge string) error {
	if len(current) == 0 {
		return errors.New("Please enter you current password")
	}

	if current == pass {
		return errors.New("Current password is the same as new password. Please set a different password.")
	}

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

	// Change password in FreeIPA
	err := client.ChangePassword(string(user.Uid), current, pass, challenge)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			log.WithFields(log.Fields{
				"uid":     user.Uid,
				"message": ierr.Message,
				"code":    ierr.Code,
			}).Error("IPA Error changing password")
			return errors.New(ierr.Message)
		}

		log.WithFields(log.Fields{
			"uid":   user.Uid,
			"error": err.Error(),
		}).Error("failed to set user password in FreeIPA")
		return errors.New("Fatal system error")
	}

	return nil
}

func (h *Handler) ChangePassword(c echo.Context) error {
	user := c.Get(ContextKeyUser).(*ipa.UserRecord)
	client := c.Get(ContextKeyIPAClient).(*ipa.Client)

	vars := map[string]interface{}{
		"user": user,
		"csrf": c.Get("csrf").(string),
	}

	if c.Request().Method == "POST" {
		current := c.FormValue("password")
		pass := c.FormValue("new_password")
		pass2 := c.FormValue("new_password2")
		challenge := c.FormValue("challenge")

		err := h.changePassword(client, user, current, pass, pass2, challenge)
		if err != nil {
			vars["message"] = err.Error()
		} else {
			vars["completed"] = true
		}
	}

	return c.Render(http.StatusOK, "change-password.html", vars)
}
