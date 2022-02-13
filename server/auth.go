package server

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func (h *Handler) LoginPost(c echo.Context) error {
	uid := c.FormValue("uid")
	password := c.FormValue("password")

	log.WithFields(log.Fields{
		"uid":      uid,
		"password": password,
	}).Info("Login attempt")

	vars := map[string]interface{}{
		"csrf":               c.Get("csrf").(string),
		"globus":             viper.GetBool("globus_signup"),
		"enable_user_signup": viper.GetBool("enable_user_signup"),
	}

	time.Sleep(time.Second * 3)
	return c.Render(http.StatusOK, "login-form.html", vars)
}

func (h *Handler) LoginGet(c echo.Context) error {
	vars := map[string]interface{}{
		"csrf":               c.Get("csrf").(string),
		"globus":             viper.GetBool("globus_signup"),
		"enable_user_signup": viper.GetBool("enable_user_signup"),
	}

	return c.Render(http.StatusOK, "login.html", vars)
}
