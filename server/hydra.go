package server

import (
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
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

func (r *Router) ConsentGet(c *fiber.Ctx) error {
	// Get the challenge from the query.
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		log.WithFields(log.Fields{
			"ip": c.IP(),
		}).Error("Consent endpoint was called without a consent challenge")
		return c.Status(fiber.StatusBadRequest).SendString("consent without challenge")
	}

	cparams := admin.NewGetConsentRequestParams()
	cparams.SetConsentChallenge(challenge)
	cparams.SetHTTPClient(r.hydraAdminHTTPClient)
	cresponse, err := r.hydraClient.Admin.GetConsentRequest(cparams)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to validate the consent challenge")
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to validate consent")
	}

	consent := cresponse.Payload

	user, err := r.adminClient.UserShow(consent.Subject)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"username": consent.Subject,
		}).Warn("Failed to find User record for consent")
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to validate consent")
	}

	params := admin.NewAcceptConsentRequestParams()
	params.SetConsentChallenge(challenge)
	params.SetHTTPClient(r.hydraAdminHTTPClient)
	params.SetBody(&models.AcceptConsentRequest{
		GrantScope: consent.RequestedScope,
		Session: &models.ConsentRequestSession{
			IDToken: map[string]interface{}{
				"uid":         string(user.Username),
				"first":       string(user.First),
				"last":        string(user.Last),
				"given_name":  string(user.First),
				"family_name": string(user.Last),
				"groups":      strings.Join(user.Groups, ";"),
				"email":       string(user.Email),
			},
		}})

	response, err := r.hydraClient.Admin.AcceptConsentRequest(params)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to accept the consent challenge")
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to accept consent")
	}

	log.WithFields(log.Fields{
		"username": consent.Subject,
	}).Info("Consent challenge signed successfully")

	c.Set("HX-Redirect", *response.Payload.RedirectTo)
	return c.Redirect(*response.Payload.RedirectTo)
}

func (r *Router) LoginOAuthGet(c *fiber.Ctx) error {
	// Get the challenge from the query.
	challenge := c.Query("login_challenge")
	if challenge == "" {
		log.WithFields(log.Fields{
			"ip": c.IP(),
		}).Error("Login OAuth endpoint was called without a challenge")
		return c.Status(fiber.StatusBadRequest).SendString("login without challenge")
	}

	getparams := admin.NewGetLoginRequestParams()
	getparams.SetLoginChallenge(challenge)
	getparams.SetHTTPClient(r.hydraAdminHTTPClient)
	response, err := r.hydraClient.Admin.GetLoginRequest(getparams)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to validate the login challenge")
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to validate login")
	}

	login := response.Payload

	if *login.Skip {
		log.WithFields(log.Fields{
			"user": login.Subject,
		}).Info("Hydra requested we skip login")

		// Check to make sure we have a valid user id
		_, err = r.adminClient.UserShow(*login.Subject)
		if err != nil {
			log.WithFields(log.Fields{
				"error":    err,
				"username": login.Subject,
			}).Warn("Failed to find User record for login")
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to validate login")
		}

		acceptparams := admin.NewAcceptLoginRequestParams()
		acceptparams.SetLoginChallenge(challenge)
		acceptparams.SetHTTPClient(r.hydraAdminHTTPClient)
		acceptparams.SetBody(&models.AcceptLoginRequest{
			Subject: login.Subject,
		})

		completedResponse, err := r.hydraClient.Admin.AcceptLoginRequest(acceptparams)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("Failed to accept the GET login challenge")
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to accept login")
		}

		log.WithFields(log.Fields{
			"username": login.Subject,
			"redirect": *completedResponse.Payload.RedirectTo,
		}).Info("Login GET challenge signed successfully")

		c.Set("HX-Redirect", *completedResponse.Payload.RedirectTo)
		return c.Redirect(*completedResponse.Payload.RedirectTo)
	}

	vars := fiber.Map{
		"challenge": challenge,
	}

	return c.Render("login.html", vars)
}

func (r *Router) LoginOAuthPost(username, challenge string, c *fiber.Ctx) error {
	acceptparams := admin.NewAcceptLoginRequestParams()
	acceptparams.SetLoginChallenge(challenge)
	acceptparams.SetHTTPClient(r.hydraAdminHTTPClient)
	acceptparams.SetBody(&models.AcceptLoginRequest{
		Subject:     &username,
		Remember:    true, // TODO: make this configurable
		RememberFor: viper.GetInt64("hydra.login_timeout"),
	})

	completedResponse, err := r.hydraClient.Admin.AcceptLoginRequest(acceptparams)
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"error":    err,
		}).Error("Failed to accept the POST login challenge")
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to accept login")
	}

	log.WithFields(log.Fields{
		"username": username,
		"redirect": *completedResponse.Payload.RedirectTo,
	}).Info("Login POST challenge signed successfully")

	c.Set("HX-Redirect", *completedResponse.Payload.RedirectTo)
	return c.Status(fiber.StatusNoContent).SendString("")
}

func (r *Router) HydraError(c *fiber.Ctx) error {
	message := c.Query("error")
	desc := c.Query("error_description")
	hint := c.Query("error_hint")

	log.WithFields(log.Fields{
		"message": message,
		"desc":    desc,
		"hint":    hint,
	}).Error("OAuth2 request failed")

	return c.Status(fiber.StatusInternalServerError).SendString("OAuth2 Error")
}

func (r *Router) revokeHydraAuthenticationSession(username string, c *fiber.Ctx) error {
	params := admin.NewRevokeAuthenticationSessionParams()
	params.SetSubject(username)
	params.SetHTTPClient(r.hydraAdminHTTPClient)
	_, err := r.hydraClient.Admin.RevokeAuthenticationSession(params)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"user": username,
	}).Info("Successfully revoked hydra authentication session")

	return nil
}
