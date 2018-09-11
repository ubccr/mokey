package server

import (
	"errors"
	"net/http"

	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
)

func (h *Handler) ApiKey(c echo.Context) error {
	if len(h.apiClients) == 0 {
		log.Info("No api key clients configured")
		return echo.NewHTTPError(http.StatusNotFound, "No api key clients configured")
	}

	user := c.Get(ContextKeyUser).(*ipa.UserRecord)

	vars := map[string]interface{}{
		"user": user,
		"csrf": c.Get("csrf").(string),
	}

	if c.Request().Method == "POST" {
		action := c.FormValue("action")
		clientID := c.FormValue("client_id")

		if clientID != "" && action == "remove" {
			err := h.removeApiKey(string(user.Uid), clientID)

			if err == nil {
				vars["message"] = "Api Key Deleted"
			} else {
				vars["message"] = err.Error()
			}
		} else if clientID != "" && action == "enable" {
			secret, client, err := h.enableApiKey(string(user.Uid), clientID)

			if err == nil {
				vars := map[string]interface{}{
					"client": client,
					"secret": secret,
					"user":   user}

				return c.Render(http.StatusOK, "apikey-show.html", vars)
			}

			vars["message"] = err.Error()
		}
	}

	keys, err := h.db.FetchApiKeys(string(user.Uid))
	if err != nil && err != model.ErrNotFound {
		log.WithFields(log.Fields{
			"uid":   string(user.Uid),
			"error": err,
		}).Error("Failed to fetch api keys")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch api keys")
	}

	keyMap := make(map[string]*model.ApiKey)
	for _, k := range keys {
		keyMap[k.ClientID] = k
	}

	vars["apiClients"] = h.apiClients
	vars["keys"] = keyMap

	return c.Render(http.StatusOK, "apikey.html", vars)
}

func (h *Handler) removeApiKey(user, clientID string) error {
	err := h.db.DestroyApiKey(user, clientID)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   user,
			"error": err,
		}).Error("Failed to remove api key")
		return errors.New("Failed to remove api key")
	}

	response, err := h.hydraClient.RevokeAuthenticationSession(user)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"user":     user,
			"clientID": clientID,
		}).Error("Failed to revoke hydra authentication session")
	} else if response.StatusCode != http.StatusNoContent {
		log.WithFields(log.Fields{
			"statusCode": response.StatusCode,
			"user":       user,
			"clientID":   clientID,
		}).Error("HTTP Response not OK. Failed to revoke hydra authentication session")
	}

	response, err = h.hydraClient.RevokeUserClientConsentSessions(user, clientID)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"user":     user,
			"clientID": clientID,
		}).Error("Failed to revoke hydra consent session")
	} else if response.StatusCode != http.StatusNoContent {
		log.WithFields(log.Fields{
			"statusCode": response.StatusCode,
			"user":       user,
			"clientID":   clientID,
		}).Error("HTTP Response not OK. Failed to revoke hydra consent session")
	}

	return nil
}

func (h *Handler) enableApiKey(user, clientID string) (string, *model.ApiKeyClient, error) {
	client, ok := h.apiClients[clientID]
	if !ok {
		log.WithFields(log.Fields{
			"uid":      user,
			"clientID": client.ClientID,
		}).Error("Invalid client ID")
		return "", nil, errors.New("Invalid client id")
	}

	_, secret, err := h.db.CreateApiKey(user, client.ClientID, client.Scopes)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":      user,
			"clientID": client.ClientID,
			"error":    err,
		}).Error("Failed to create new api key")
		return "", nil, errors.New("Fatal system error. Please contact your administrator")
	}

	return secret, client, nil
}
