package server

import (
	"errors"
	"net/http"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra-client-go/client/admin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
)

func (h *Handler) tryAuth(uid, password string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("Please provide a password")
	}

	client := ipa.NewDefaultClient()

	err := client.RemoteLogin(uid, password)
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
		log.WithFields(log.Fields{
			"uid":              uid,
			"ipa_client_error": err,
		}).Error("Failed to ping FreeIPA")
		return "", errors.New("Error contacting FreeIPA")
	}

	return client.SessionID(), nil
}

func (h *Handler) LoginPost(c echo.Context) error {
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
		"csrf":               c.Get("csrf").(string),
		"globus":             viper.GetBool("globus_signup"),
		"enable_user_signup": viper.GetBool("enable_user_signup"),
		"message":            message}

	return c.Render(http.StatusOK, "login.html", vars)
}

func (h *Handler) LoginGet(c echo.Context) error {
	vars := map[string]interface{}{
		"csrf":               c.Get("csrf").(string),
		"globus":             viper.GetBool("globus_signup"),
		"enable_user_signup": viper.GetBool("enable_user_signup"),
	}

	return c.Render(http.StatusOK, "login.html", vars)
}

func (h *Handler) Logout(c echo.Context) error {
	err := h.revokeHydraAuthenticationSession(c)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Warn("Logout - Failed to revoke hydra authentication session")
	}

	logout(c)
	return c.Redirect(http.StatusFound, Path("/auth/login"))
}

func (h Handler) revokeHydraAuthenticationSession(c echo.Context) error {
	if !viper.IsSet("hydra_admin_url") {
		return nil
	}

	sess, err := session.Get(CookieKeySession, c)
	if err != nil {
		return err
	}

	sid := sess.Values[CookieKeySID]
	user := sess.Values[CookieKeyUser]

	if sid == nil || user == nil {
		return errors.New("No sid or user found in session")
	}

	if _, ok := user.(string); !ok {
		return errors.New("User is not a string")
	}

	client := ipa.NewDefaultClientWithSession(sid.(string))

	userRec, err := client.UserShow(user.(string))
	if err != nil {
		return err
	}

	params := admin.NewRevokeAuthenticationSessionParams()
	params.SetSubject(string(userRec.Uid))
	_, err = h.hydraClient.Admin.RevokeAuthenticationSession(params)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"user": userRec.Uid,
	}).Info("Successfully revoked hydra authentication session")

	return nil
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
