package server

import (
	"net/http"
	"strings"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type FakeTLSTransport struct {
	T http.RoundTripper
}

func (ftt *FakeTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("X-Forwarded-Proto", "https")
	return ftt.T.RoundTrip(req)
}

func (h *Handler) ConsentGet(c echo.Context) error {
	// Get the challenge from the query.
	challenge := c.Request().URL.Query().Get("consent_challenge")
	if challenge == "" {
		log.WithFields(log.Fields{
			"ip": c.RealIP(),
		}).Error("Consent endpoint was called without a consent challenge")
		return echo.NewHTTPError(http.StatusBadRequest, "consent without challenge")
	}

	params := admin.NewGetConsentRequestParams()
	params.SetConsentChallenge(challenge)
	params.SetHTTPClient(h.hydraAdminHTTPClient)
	response, err := h.hydraClient.Admin.GetConsentRequest(params)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to validate the consent challenge")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate consent")
	}

	consent := response.Payload

	user, err := h.client.UserShow(consent.Subject)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"username": consent.Subject,
		}).Warn("Failed to find User record for consent")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate consent")
	}

	if viper.GetBool("hydra_consent_skip") || consent.Skip {
		log.WithFields(log.Fields{
			"user": consent.Subject,
		}).Info("Hydra requested we skip consent")

		// Check to make sure we have a valid user id
		_, err = h.client.UserShow(consent.Subject)
		if err != nil {
			log.WithFields(log.Fields{
				"error":    err,
				"username": consent.Subject,
			}).Warn("Failed to find User record for consent")
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate consent")
		}

		params := admin.NewAcceptConsentRequestParams()
		params.SetConsentChallenge(challenge)
		params.SetHTTPClient(h.hydraAdminHTTPClient)
		params.SetBody(&models.AcceptConsentRequest{
			GrantScope: consent.RequestedScope,
			Session: &models.ConsentRequestSession{
				IDToken: map[string]interface{}{
					"uid":         string(user.Uid),
					"first":       string(user.First),
					"last":        string(user.Last),
					"given_name":  string(user.First),
					"family_name": string(user.Last),
					"groups":      strings.Join(user.Groups, ";"),
					"email":       string(user.Email),
				},
			}})

		response, err := h.hydraClient.Admin.AcceptConsentRequest(params)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("Failed to accept the consent challenge")
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to accept consent")
		}

		log.WithFields(log.Fields{
			"username": consent.Subject,
		}).Info("Consent challenge signed successfully")

		return c.Redirect(http.StatusFound, *response.Payload.RedirectTo)
	}

	vars := map[string]interface{}{
		"csrf":      c.Get("csrf").(string),
		"consent":   consent,
		"challenge": challenge,
		"firstName": user.First,
	}

	return c.Render(http.StatusOK, "consent.html", vars)
}

func (h *Handler) ConsentPost(c echo.Context) error {
	if err := c.Request().ParseForm(); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to parse form")
		return echo.NewHTTPError(http.StatusBadRequest, "failed to parse form")
	}

	challenge := c.FormValue("challenge")
	if challenge == "" {
		log.WithFields(log.Fields{
			"ip": c.RealIP(),
		}).Error("Consent endpoint was called without a consent challenge")
		return echo.NewHTTPError(http.StatusBadRequest, "consent without challenge")
	}

	getparams := admin.NewGetConsentRequestParams()
	getparams.SetConsentChallenge(challenge)
	getparams.SetHTTPClient(h.hydraAdminHTTPClient)
	response, err := h.hydraClient.Admin.GetConsentRequest(getparams)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to validate the consent challenge")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate consent")
	}

	consent := response.Payload

	user, err := h.client.UserShow(consent.Subject)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"username": consent.Subject,
		}).Warn("Failed to find User record for consent")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate consent")
	}

	grantedScopes := c.Request().PostForm["scope"]
	if grantedScopes == nil {
		grantedScopes = []string{}
	}

	acceptparams := admin.NewAcceptConsentRequestParams()
	acceptparams.SetConsentChallenge(challenge)
	acceptparams.SetHTTPClient(h.hydraAdminHTTPClient)
	acceptparams.SetBody(&models.AcceptConsentRequest{
		GrantScope:  grantedScopes,
		Remember:    true, // TODO: make this configurable
		RememberFor: viper.GetInt64("hydra_consent_timeout"),
		Session: &models.ConsentRequestSession{
			IDToken: map[string]interface{}{
				"uid":         string(user.Uid),
				"first":       string(user.First),
				"last":        string(user.Last),
				"given_name":  string(user.First),
				"family_name": string(user.Last),
				"groups":      strings.Join(user.Groups, ";"),
				"email":       string(user.Email),
			},
		}})

	completedResponse, err := h.hydraClient.Admin.AcceptConsentRequest(acceptparams)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to accept the consent challenge")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to accept consent")
	}

	log.WithFields(log.Fields{
		"username": string(user.Uid),
	}).Info("Consent challenge signed successfully")

	return c.Redirect(http.StatusFound, *completedResponse.Payload.RedirectTo)
}

func (h *Handler) LoginOAuthGet(c echo.Context) error {
	// Get the challenge from the query.
	challenge := c.Request().URL.Query().Get("login_challenge")
	if challenge == "" {
		log.WithFields(log.Fields{
			"ip": c.RealIP(),
		}).Error("Login OAuth endpoint was called without a challenge")
		return echo.NewHTTPError(http.StatusBadRequest, "login without challenge")
	}

	getparams := admin.NewGetLoginRequestParams()
	getparams.SetLoginChallenge(challenge)
	getparams.SetHTTPClient(h.hydraAdminHTTPClient)
	response, err := h.hydraClient.Admin.GetLoginRequest(getparams)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to validate the login challenge")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate login")
	}

	login := response.Payload

	if *login.Skip {
		log.WithFields(log.Fields{
			"user": login.Subject,
		}).Info("Hydra requested we skip login")

		// Check to make sure we have a valid user id
		_, err = h.client.UserShow(*login.Subject)
		if err != nil {
			log.WithFields(log.Fields{
				"error":    err,
				"username": login.Subject,
			}).Warn("Failed to find User record for login")
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate login")
		}

		acceptparams := admin.NewAcceptLoginRequestParams()
		acceptparams.SetLoginChallenge(challenge)
		acceptparams.SetHTTPClient(h.hydraAdminHTTPClient)
		acceptparams.SetBody(&models.AcceptLoginRequest{
			Subject: login.Subject,
		})

		completedResponse, err := h.hydraClient.Admin.AcceptLoginRequest(acceptparams)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("Failed to accept the login challenge")
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to accept login")
		}

		log.WithFields(log.Fields{
			"username": login.Subject,
		}).Info("Login challenge signed successfully")

		return c.Redirect(http.StatusFound, *completedResponse.Payload.RedirectTo)
	}

	vars := map[string]interface{}{
		"csrf":      c.Get("csrf").(string),
		"challenge": challenge,
	}

	return c.Render(http.StatusOK, "login-oauth.html", vars)
}

func (h *Handler) LoginOAuthPost(c echo.Context) error {
	message := ""
	uid := c.FormValue("uid")
	password := c.FormValue("password")
	challenge := c.FormValue("challenge")

	var sid string
	sid, err := h.tryAuth(uid, password)
	if err == nil {
		sess, _ := session.Get(CookieKeySession, c)
		sess.Values[CookieKeyUser] = uid
		sess.Values[CookieKeySID] = sid
		sess.Values[CookieKeyAuthenticated] = true
		delete(sess.Values, CookieKeyWYAF)
		sess.Save(c.Request(), c.Response())
	}

	if err == nil {
		acceptparams := admin.NewAcceptLoginRequestParams()
		acceptparams.SetLoginChallenge(challenge)
		acceptparams.SetHTTPClient(h.hydraAdminHTTPClient)
		acceptparams.SetBody(&models.AcceptLoginRequest{
			Subject:     &uid,
			Remember:    true, // TODO: make this configurable
			RememberFor: viper.GetInt64("hydra_login_timeout"),
		})

		completedResponse, err := h.hydraClient.Admin.AcceptLoginRequest(acceptparams)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("Failed to accept the login challenge")
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to accept login")
		}

		log.WithFields(log.Fields{
			"username": uid,
		}).Info("Login challenge signed successfully")

		return c.Redirect(http.StatusFound, *completedResponse.Payload.RedirectTo)
	}

	message = err.Error()

	vars := map[string]interface{}{
		"csrf":      c.Get("csrf").(string),
		"challenge": challenge,
		"message":   message}

	return c.Render(http.StatusOK, "login-oauth.html", vars)
}

func (h *Handler) HydraError(c echo.Context) error {
	message := c.Request().URL.Query().Get("error")
	desc := c.Request().URL.Query().Get("error_description")
	hint := c.Request().URL.Query().Get("error_hint")

	log.WithFields(log.Fields{
		"message": message,
		"desc":    desc,
		"hint":    hint,
	}).Error("OAuth2 request failed")

	return echo.NewHTTPError(http.StatusInternalServerError, "OAuth2 Error")
}
