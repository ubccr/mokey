package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo"
	"github.com/ory/hydra/sdk/go/hydra/client/admin"
	"github.com/ory/hydra/sdk/go/hydra/models"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/mokey/model"
)

type FakeTLSTransport struct {
	T http.RoundTripper
}

func (ftt *FakeTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("X-Forwarded-Proto", "https")
	return ftt.T.RoundTrip(req)
}

func (h *Handler) ConsentGet(c echo.Context) error {
	apiKey, err := h.checkApiKey(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid api key")
	}

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

	if consent.Skip {
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
		params.SetBody(&models.HandledConsentRequest{
			GrantedScope: consent.RequestedScope,
			Session: &models.ConsentRequestSessionData{
				IDToken: map[string]interface{}{
					"uid":    string(user.Uid),
					"first":  string(user.First),
					"last":   string(user.Last),
					"groups": strings.Join(user.Groups, ";"),
					"email":  string(user.Email),
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

		return c.Redirect(http.StatusFound, response.Payload.RedirectTo)
	}

	if apiKey != nil && strings.Contains(c.Request().Header.Get("Accept"), "application/json") {
		data := map[string]string{
			"csrf":      c.Get("csrf").(string),
			"client_id": consent.Client.ClientID,
			"scopes":    strings.Join(consent.RequestedScope, ","),
			"challenge": challenge,
		}

		return c.JSON(http.StatusOK, data)
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
	acceptparams.SetBody(&models.HandledConsentRequest{
		GrantedScope: grantedScopes,
		Remember:     true, // TODO: make this configurable
		RememberFor:  viper.GetInt64("hydra_consent_timeout"),
		Session: &models.ConsentRequestSessionData{
			IDToken: map[string]interface{}{
				"uid":    string(user.Uid),
				"first":  string(user.First),
				"last":   string(user.Last),
				"groups": strings.Join(user.Groups, ";"),
				"email":  string(user.Email),
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

	return c.Redirect(http.StatusFound, completedResponse.Payload.RedirectTo)
}

func (h *Handler) LoginOAuthGet(c echo.Context) error {
	apiKey, err := h.checkApiKey(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid api key")
	}

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

	if login.Skip {
		log.WithFields(log.Fields{
			"user": login.Subject,
		}).Info("Hydra requested we skip login")

		// Check to make sure we have a valid user id
		_, err = h.client.UserShow(login.Subject)
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
		acceptparams.SetBody(&models.HandledLoginRequest{
			Subject: &login.Subject,
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

		return c.Redirect(http.StatusFound, completedResponse.Payload.RedirectTo)
	}

	if apiKey != nil && strings.Contains(c.Request().Header.Get("Accept"), "application/json") {
		data := map[string]string{
			"csrf":      c.Get("csrf").(string),
			"client_id": login.Client.ClientID,
			"scopes":    strings.Join(login.RequestedScope, ","),
			"challenge": challenge,
		}

		return c.JSON(http.StatusOK, data)
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
	apiKey, err := h.checkApiKey(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid api key")
	}

	if apiKey != nil {
		getparams := admin.NewGetLoginRequestParams()
		getparams.SetLoginChallenge(challenge)
		getparams.SetHTTPClient(h.hydraAdminHTTPClient)
		response, err := h.hydraClient.Admin.GetLoginRequest(getparams)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("Failed to validate the apikey login challenge")
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate login")
		}

		login := response.Payload

		log.WithFields(log.Fields{
			"user":      apiKey.UserName,
			"client_id": login.Client.ClientID,
		}).Info("Api consent request")

		// Check key matches client
		if apiKey.ClientID != login.Client.ClientID {
			log.WithFields(log.Fields{
				"key":              apiKey.Key,
				"user":             apiKey.UserName,
				"apikey_client_id": apiKey.ClientID,
				"client_id":        login.Client.ClientID,
			}).Error("Claims client id does not match api key")
			return echo.NewHTTPError(http.StatusBadRequest, "Claims client id does not match api key")
		}

		uid = apiKey.UserName
	} else {
		_, err = h.tryAuth(uid, password)
	}

	if err == nil {
		acceptparams := admin.NewAcceptLoginRequestParams()
		acceptparams.SetLoginChallenge(challenge)
		acceptparams.SetHTTPClient(h.hydraAdminHTTPClient)
		acceptparams.SetBody(&models.HandledLoginRequest{
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

		return c.Redirect(http.StatusFound, completedResponse.Payload.RedirectTo)
	}

	message = err.Error()

	vars := map[string]interface{}{
		"csrf":      c.Get("csrf").(string),
		"challenge": challenge,
		"message":   message}

	return c.Render(http.StatusOK, "login-oauth.html", vars)
}

func (h *Handler) checkApiKey(c echo.Context) (*model.ApiKey, error) {
	accept := c.Request().Header.Get("Accept")
	auth := strings.Split(c.Request().Header.Get("Authorization"), " ")
	apiKeyString := ""
	if strings.Contains(accept, "application/json") &&
		len(auth) == 2 && strings.ToLower(auth[0]) == "bearer" &&
		len(auth[1]) > 0 {

		apiKeyString = auth[1]
	}

	if len(apiKeyString) == 0 {
		return nil, nil
	}

	key, err := h.db.FetchApiKey(apiKeyString)
	if err != nil {
		log.WithFields(log.Fields{
			"key":   apiKeyString,
			"error": err,
		}).Error("Failed to fetch api key")
		return nil, err
	}

	// Check api client is enabled in config
	if _, ok := h.apiClients[key.ClientID]; !ok {
		log.WithFields(log.Fields{
			"key":       key.Key,
			"user":      key.UserName,
			"client_id": key.ClientID,
		}).Error("Api client is not enabled in mokey.yaml")
		return nil, errors.New("Invalid api client")
	}

	err = h.db.RefreshApiKey(key)
	if err != nil {
		log.WithFields(log.Fields{
			"key":   apiKeyString,
			"error": err,
		}).Error("Failed to save api key")
		return nil, err
	}

	_, err = h.client.UserShow(key.UserName)
	if err != nil {
		log.WithFields(log.Fields{
			"key":   apiKeyString,
			"user":  key.UserName,
			"error": err,
		}).Error("Failed to fetch user from ipa")
		return nil, err
	}

	return key, nil
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
