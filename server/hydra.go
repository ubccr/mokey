package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo"
	"github.com/ory/hydra/sdk"
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

	// Verify the challenge and extract the challenge claims.
	claims, err := h.hydraClient.Consent.VerifyChallenge(challenge)
	if err != nil {
		log.WithFields(log.Fields{
			"user": string(user.Uid),
		}).Error("The consent challenge could not be verified")
		return echo.NewHTTPError(http.StatusBadRequest, "invalid challenge")
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
				"audience":  claims.Audience,
			}).Info("Api consent request")

			// Check key matches client
			if apiKey.ClientID != claims.Audience {
				log.WithFields(log.Fields{
					"key":       apiKey.Key,
					"user":      apiKey.UserName,
					"client_id": apiKey.ClientID,
					"audience":  claims.Audience,
				}).Error("Claims audience does not match api key")
				return echo.NewHTTPError(http.StatusBadRequest, "Claims audience does not match api key")
			}

			// Check key matches scopes
			if apiKey.Scopes != strings.Join(claims.RequestedScopes, ",") {
				log.WithFields(log.Fields{
					"key":           apiKey.Key,
					"user":          apiKey.UserName,
					"key_scopes":    apiKey.Scopes,
					"claims_scopes": claims.RequestedScopes,
				}).Error("Claims scopes does not match api key")
				return echo.NewHTTPError(http.StatusBadRequest, "Claims scopes does not match api key")
			}
		}

		// Generate the challenge response.
		redirectUrl, err := h.hydraClient.Consent.GenerateResponse(&sdk.ResponseRequest{
			// We need to include the original challenge.
			Challenge: challenge,

			// The subject is a string, usually the user id.
			Subject: string(user.Uid),

			// The scopes our user granted.
			Scopes: grantedScopes,

			// Data that will be available on the token introspection and warden endpoints.
			AccessTokenExtra: struct {
				UID    string `json:"uid"`
				First  string `json:"first"`
				Last   string `json:"last"`
				Email  string `json:"email"`
				Groups string `json:"groups"`
			}{
				UID:    string(user.Uid),
				First:  string(user.First),
				Last:   string(user.Last),
				Groups: strings.Join(user.Groups, ";"),
				Email:  string(user.Email)},

			// If we issue an ID token, we can set extra data for that id token here.
			IDTokenExtra: struct {
				UID    string `json:"uid"`
				First  string `json:"first"`
				Last   string `json:"last"`
				Email  string `json:"email"`
				Groups string `json:"groups"`
			}{
				UID:    string(user.Uid),
				First:  string(user.First),
				Last:   string(user.Last),
				Groups: strings.Join(user.Groups, ";"),
				Email:  string(user.Email)},
		})

		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("Could not sign the consent challenge")
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to sign consent")
		}

		log.WithFields(log.Fields{
			"redirectURL": redirectUrl,
		}).Info("Consent challenge signed successfully")

		return c.Redirect(http.StatusFound, redirectUrl)
	}

	if strings.Contains(c.Request().Header.Get("Accept"), "application/json") {
		data := map[string]string{
			"csrf":      c.Get("csrf").(string),
			"audience":  claims.Audience,
			"scopes":    strings.Join(claims.RequestedScopes, ","),
			"challenge": challenge,
		}

		return c.JSON(http.StatusOK, data)
	}

	vars["claims"] = claims
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
