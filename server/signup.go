package server

import (
	"bytes"
	"errors"
	"net/http"
	"path"
	"path/filepath"
	"time"

	valid "github.com/asaskevich/govalidator"
	"github.com/dchest/captcha"
	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
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

func (h *Handler) createAccount(uid, email, first, last, captchaID, captchaSol string) error {
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

	_, err := h.client.UserAdd(uid, email, first, last, homedir, viper.GetString("default_shell"))
	if err != nil {
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

	return nil
}

func (h *Handler) Signup(c echo.Context) error {
	message := ""
	success := false

	if c.Request().Method == "POST" {
		uid := c.FormValue("uid")
		email := c.FormValue("email")
		first := c.FormValue("first")
		last := c.FormValue("last")
		captchaID := c.FormValue("captcha_id")
		captchaSol := c.FormValue("captcha_sol")

		err := h.createAccount(uid, email, first, last, captchaID, captchaSol)
		if err != nil {
			message = err.Error()
		} else {
			success = true
		}
	}

	vars := map[string]interface{}{
		"success": success,
		"message": message,
		"csrf":    c.Get("csrf").(string),
	}

	if viper.GetBool("enable_captcha") {
		vars["captchaID"] = captcha.New()
	}

	return c.Render(http.StatusOK, "signup.html", vars)
}
