package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
)

func (h *Handler) Consent(c echo.Context) error {
	apiKey, err := h.checkApiKey(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid api key")
	}
	user := c.Get(ContextKeyUser).(*ipa.UserRecord)

	vars := map[string]interface{}{
		"user": user,
		"csrf": c.Get("csrf").(string),
	}

	// Get the challenge from the query.
	challenge := c.Request().URL.Query().Get("challenge")
	if challenge == "" {
		log.WithFields(log.Fields{
			"user": string(user.Uid),
		}).Error("Consent endpoint was called without a consent challenge")
		return echo.NewHTTPError(http.StatusBadRequest, "consent without challenge")
	}

	consent, response, err := h.hydraClient.GetConsentRequest(challenge)
	if err != nil {
		// This usually indicates a network error.
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to validate the consent challenge")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate consent")
	} else if response.StatusCode != http.StatusOK {
		// This usually indicates a network error.
		log.WithFields(log.Fields{
			"error":      err,
			"statusCode": response.StatusCode,
		}).Error("Failed to validate the consent challenge")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate consent")
	}

	if c.Request().Method == "POST" {
		if err := c.Request().ParseForm(); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("Failed to parse form")
			return echo.NewHTTPError(http.StatusBadRequest, "failed to parse form")
		}

		grantedScopes := c.Request().PostForm["scope"]
		if grantedScopes == nil {
			grantedScopes = []string{}
		}

		if apiKey != nil {
			log.WithFields(log.Fields{
				"user":      apiKey.UserName,
				"client_id": apiKey.ClientID,
				"audience":  consent.Subject,
			}).Info("Api consent request")

			// Check key matches client
			if apiKey.ClientID != consent.Subject {
				log.WithFields(log.Fields{
					"key":       apiKey.Key,
					"user":      apiKey.UserName,
					"client_id": apiKey.ClientID,
					"audience":  consent.Subject,
				}).Error("Consent subject does not match api key")
				return echo.NewHTTPError(http.StatusBadRequest, "Consent subject does not match api key")
			}

			// Check key matches scopes
			if apiKey.Scopes != strings.Join(consent.RequestedScope, ",") {
				log.WithFields(log.Fields{
					"key":           apiKey.Key,
					"user":          apiKey.UserName,
					"key_scopes":    apiKey.Scopes,
					"claims_scopes": consent.RequestedScope,
				}).Error("Requested scopes does not match api key")
				return echo.NewHTTPError(http.StatusBadRequest, "Requested scopes does not match api key")
			}
		}

		completedRequest, response, err := h.hydraClient.AcceptConsentRequest(challenge, swagger.AcceptConsentRequest{
			GrantScope:  grantedScopes,
			Remember:    true,
			RememberFor: 3600,
			Session: swagger.ConsentRequestSession{
				IdToken: map[string]interface{}{
					"uid":    string(user.Uid),
					"first":  string(user.First),
					"last":   string(user.Last),
					"groups": strings.Join(user.Groups, ";"),
					"email":  string(user.Email),
				},
			},
		})

		if err != nil {
			// This usually indicates a network error.
			log.WithFields(log.Fields{
				"error": err,
			}).Error("Failed to accept the consent challenge")
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to accept consent")
		} else if response.StatusCode != http.StatusCreated {
			log.WithFields(log.Fields{
				"error":      err,
				"statusCode": response.StatusCode,
			}).Error("Failed to accept the consent challenge")
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to accept consent")
		}

		log.WithFields(log.Fields{
			"redirectURL": completedRequest.RedirectTo,
		}).Info("Consent challenge signed successfully")

		return c.Redirect(http.StatusFound, completedRequest.RedirectTo)
	}

	if strings.Contains(c.Request().Header.Get("Accept"), "application/json") {
		data := map[string]string{
			"csrf":      c.Get("csrf").(string),
			"audience":  consent.Subject,
			"scopes":    strings.Join(consent.RequestedScope, ","),
			"challenge": challenge,
		}

		return c.JSON(http.StatusOK, data)
	}

	vars["consent"] = consent
	vars["challenge"] = challenge
	vars["firstName"] = user.First

	return c.Render(http.StatusOK, "consent.html", vars)
}

func (h *Handler) checkApiKey(c echo.Context) (*model.ApiKey, error) {
	apiKeyString := c.Get(ContextKeyApi)
	if apiKeyString == nil {
		return nil, nil
	}

	key, err := h.db.FetchApiKey(apiKeyString.(string))
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

	userRec, err := h.client.UserShow(key.UserName)
	if err != nil {
		log.WithFields(log.Fields{
			"key":   apiKeyString,
			"user":  key.UserName,
			"error": err,
		}).Error("Failed to fetch user from ipa")
		return nil, err
	}

	c.Set(ContextKeyUser, userRec)

	return key, nil
}
