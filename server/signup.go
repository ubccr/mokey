package server

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"time"

	valid "github.com/asaskevich/govalidator"
	"github.com/dchest/captcha"
	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/util"
)

func init() {
	viper.SetDefault("enable_captcha", true)
	viper.SetDefault("default_shell", "/bin/bash")
	viper.SetDefault("default_homedir", "/home")
}

// Captcha handler displays captcha image
func (h *Handler) Captcha(c echo.Context) error {
	_, file := path.Split(c.Request().URL.Path)
	ext := path.Ext(file)
	id := file[:len(file)-len(ext)]
	if ext == "" || id == "" {
		return echo.NewHTTPError(http.StatusNotFound, "Captcha not found")
	}
	if c.Request().FormValue("reload") != "" {
		captcha.Reload(id)
	}

	c.Response().Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Response().Header().Set("Pragma", "no-cache")
	c.Response().Header().Set("Expires", "0")

	var content bytes.Buffer
	switch ext {
	case ".png":
		c.Response().Header().Set(echo.HeaderContentType, "image/png")
		err := captcha.WriteImage(&content, id, captcha.StdWidth, captcha.StdHeight)
		if err != nil {
			log.WithFields(log.Fields{
				"id": id,
			}).Warn("Captcha not found")
			return echo.NewHTTPError(http.StatusNotFound, "Captcha not found")
		}
	default:
		return echo.NewHTTPError(http.StatusNotFound, "Captcha not found")
	}

	http.ServeContent(c.Response(), c.Request(), id+ext, time.Time{}, bytes.NewReader(content.Bytes()))
	return nil
}

func (h *Handler) createAccount(uid, email, first, last, pass, pass2, captchaID, captchaSol string) error {
	if !valid.IsEmail(email) {
		return errors.New("Please provide a valid email address")
	}

	if len(uid) <= 2 || len(uid) > 50 {
		return errors.New("Please provide a username")
	}

	if !valid.IsAlphanumeric(uid) {
		return errors.New("Username must be alpha numeric")
	}

	if len(first) == 0 || len(first) > 150 {
		return errors.New("Please provide your first name")
	}

	if len(last) == 0 || len(last) > 150 {
		return errors.New("Please provide your last name")
	}

	if err := util.CheckPassword(pass, viper.GetInt("min_passwd_len"), viper.GetInt("min_passwd_classes")); err != nil {
		return err
	}

	if pass != pass2 {
		return errors.New("Password do not match. Please confirm your password.")
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

	homedir := filepath.Join(viper.GetString("default_homedir"), uid)

	userRec, err := h.client.UserAdd(uid, email, first, last, homedir, viper.GetString("default_shell"), true)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			if ierr.Code == 4002 {
				return fmt.Errorf("Username already exists: %s", uid)
			} else {
				log.WithFields(log.Fields{
					"code": ierr.Code,
				}).Error("Unknown IPA error when creating new user account")
			}
		}

		log.WithFields(log.Fields{
			"err":     err,
			"uid":     uid,
			"email":   email,
			"first":   first,
			"last":    last,
			"homedir": homedir,
		}).Error("Failed to create user account")
		return errors.New("Failed to create user account. Fatal system error.")
	}

	log.WithFields(log.Fields{
		"uid":     uid,
		"email":   email,
		"first":   first,
		"last":    last,
		"homedir": homedir,
	}).Info("New user account created")

	// Set password
	err = h.client.SetPassword(uid, userRec.Randompassword, pass, "")
	if err != nil {
		log.WithFields(log.Fields{
			"err":   err,
			"uid":   uid,
			"email": email,
		}).Error("Failed to set password for user")

		// TODO: need to handle this case better
		return errors.New("There was a problem creating your account. Please contact the administrator")
	}

	log.WithFields(log.Fields{
		"uid": uid,
	}).Info("User password set successfully")

	// Send user an email to verify their account
	err = h.NewAccountEmail(uid, email)
	if err != nil {
		log.WithFields(log.Fields{
			"err":   err,
			"uid":   uid,
			"email": email,
		}).Error("Failed to send new account email")
		return errors.New("Failed to create user account. Fatal system error.")
	}

	log.WithFields(log.Fields{
		"uid":   uid,
		"email": email,
	}).Info("New user account email sent successfully")

	return nil
}

func (h *Handler) CreateAccount(c echo.Context) error {
	uid := c.FormValue("uid")
	email := c.FormValue("email")
	first := c.FormValue("first")
	last := c.FormValue("last")
	pass := c.FormValue("password")
	pass2 := c.FormValue("password2")
	captchaID := c.FormValue("captcha_id")
	captchaSol := c.FormValue("captcha_sol")

	vars := map[string]interface{}{
		"csrf": c.Get("csrf").(string),
	}

	if viper.GetBool("enable_captcha") {
		vars["captchaID"] = captcha.New()
	}

	err := h.createAccount(uid, email, first, last, pass, pass2, captchaID, captchaSol)
	if err != nil {
		vars["message"] = err.Error()
	} else {
		vars["success"] = true
	}

	return c.Render(http.StatusOK, "signup.html", vars)
}

func (h *Handler) Signup(c echo.Context) error {
	vars := map[string]interface{}{
		"csrf": c.Get("csrf").(string),
	}

	if viper.GetBool("enable_captcha") {
		vars["captchaID"] = captcha.New()
	}

	return c.Render(http.StatusOK, "signup.html", vars)
}
