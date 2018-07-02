package server

import (
	"errors"
	"net/http"

	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
)

func (h *Handler) tryAuth(uid, password string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("Please provide a password")
	}

	client := ipa.NewDefaultClient()

	err := client.Login(uid, password)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":              uid,
			"ipa_client_error": err,
		}).Error("Failed login attempt")
		return "", errors.New("Invalid login")
	}

	// Ping to get sessionID for later use
	_, err = client.Ping()
	if err != nil {
		return "", errors.New("Error contacting FreeIPA")
	}

	return client.SessionID(), nil
}

func (h *Handler) Login(c echo.Context) error {
	message := ""
	sess, _ := session.Get(CookieKeySession, c)

	uid := c.FormValue("uid")
	password := c.FormValue("password")

	sid, err := h.tryAuth(uid, password)
	if err == nil {
		sess.Values[CookieKeyUser] = uid
		sess.Values[CookieKeySID] = sid
		sess.Values[CookieKeyAuthenticated] = true

		location := Path("/")
		wyaf := sess.Values[CookieKeyWYAF]
		if _, ok := wyaf.(string); ok {
			location = wyaf.(string)
		}
		delete(sess.Values, CookieKeyWYAF)

		sess.Save(c.Request(), c.Response())

		return c.Redirect(http.StatusFound, location)
	} else {
		message = err.Error()
	}

	vars := map[string]interface{}{
		"csrf":    c.Get("csrf").(string),
		"globus":  viper.GetBool("globus_signup"),
		"message": message}

	return c.Render(http.StatusOK, "login.html", vars)
}

func (h *Handler) Signin(c echo.Context) error {
	vars := map[string]interface{}{
		"csrf":   c.Get("csrf").(string),
		"globus": viper.GetBool("globus_signup"),
	}

	return c.Render(http.StatusOK, "login.html", vars)
}

func (h *Handler) Logout(c echo.Context) error {
	logout(c)
	return c.Redirect(http.StatusFound, Path("/auth/login"))
}

func logout(c echo.Context) {
	sess, _ := session.Get(CookieKeySession, c)
	delete(sess.Values, CookieKeySID)
	delete(sess.Values, CookieKeyUser)
	delete(sess.Values, CookieKeyAuthenticated)
	delete(sess.Values, CookieKeyWYAF)
	delete(sess.Values, CookieKeyGlobus)
	delete(sess.Values, CookieKeyGlobusUsername)
	sess.Options.MaxAge = -1

	sess.Save(c.Request(), c.Response())
}
