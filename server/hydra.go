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
			"ip": RemoteIP(c),
		}).Error("Consent endpoint was called without a consent challenge")
		r.metrics.totalHydraFailedLogins.Inc()
		return c.Status(fiber.StatusBadRequest).SendString(Translate("", "hydra.consent_without_challenge"))
	}

	cparams := admin.NewGetConsentRequestParams()
	cparams.SetConsentChallenge(challenge)
	cparams.SetHTTPClient(r.hydraAdminHTTPClient)
	cresponse, err := r.hydraClient.Admin.GetConsentRequest(cparams)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to validate the consent challenge")
		r.metrics.totalHydraFailedLogins.Inc()
		return c.Status(fiber.StatusInternalServerError).SendString(Translate("", "hydra.failed_to_validate_consent"))
	}

	consent := cresponse.Payload

	user, err := r.adminClient.UserShow(consent.Subject)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"username": consent.Subject,
		}).Warn("Failed to find User record for consent")
		r.metrics.totalHydraFailedLogins.Inc()
		return c.Status(fiber.StatusInternalServerError).SendString(Translate("", "hydra.failed_to_validate_consent"))
	}

	if viper.GetBool("accounts.require_mfa") && !user.OTPOnly() {
		r.metrics.totalHydraFailedLogins.Inc()
		return c.Status(fiber.StatusUnauthorized).SendString(Translate("", "hydra.access_denied"))
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
		r.metrics.totalHydraFailedLogins.Inc()
		return c.Status(fiber.StatusInternalServerError).SendString(Translate("", "hydra.failed_to_accept_consent"))
	}

	log.WithFields(log.Fields{
		"username": consent.Subject,
	}).Info("AUDIT User logged in via Hydra OAuth2 successfully")
	r.metrics.totalHydraLogins.Inc()

	c.Set("HX-Redirect", *response.Payload.RedirectTo)
	return c.Redirect(*response.Payload.RedirectTo)
}

func (r *Router) LoginOAuthGet(c *fiber.Ctx) error {
	// Get the challenge from the query.
	challenge := c.Query("login_challenge")
	if challenge == "" {
		log.WithFields(log.Fields{
			"ip": RemoteIP(c),
		}).Error("Login OAuth endpoint was called without a challenge")
		return c.Status(fiber.StatusBadRequest).SendString(Translate("", "hydra.login_without_challenge"))
	}

	getparams := admin.NewGetLoginRequestParams()
	getparams.SetLoginChallenge(challenge)
	getparams.SetHTTPClient(r.hydraAdminHTTPClient)
	response, err := r.hydraClient.Admin.GetLoginRequest(getparams)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to validate the login challenge")
		return c.Status(fiber.StatusInternalServerError).SendString(Translate("", "hydra.failed_to_validate_login"))
	}

	login := response.Payload

	if *login.Skip {
		log.WithFields(log.Fields{
			"user": *login.Subject,
		}).Debug("Hydra requested we skip login")

		// Check to make sure we have a valid user id
		user, err := r.adminClient.UserShow(*login.Subject)
		if err != nil {
			log.WithFields(log.Fields{
				"error":    err,
				"username": *login.Subject,
			}).Warn("Failed to find User record for login")
			r.metrics.totalHydraFailedLogins.Inc()
			return c.Status(fiber.StatusInternalServerError).SendString(Translate("", "hydra.failed_to_validate_login"))
		}

		if viper.GetBool("accounts.require_mfa") && !user.OTPOnly() {
			r.metrics.totalHydraFailedLogins.Inc()
			return c.Status(fiber.StatusUnauthorized).SendString(Translate("", "hydra.access_denied"))
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
			r.metrics.totalHydraFailedLogins.Inc()
			return c.Status(fiber.StatusInternalServerError).SendString(Translate("", "hydra.failed_to_accept_login"))
		}

		log.WithFields(log.Fields{
			"username": *login.Subject,
		}).Debug("Hydra OAuth login GET challenge signed successfully")

		c.Set("HX-Redirect", *completedResponse.Payload.RedirectTo)
		return c.Redirect(*completedResponse.Payload.RedirectTo)
	}

	if ok, _ := r.isLoggedIn(c); ok {
		return r.LoginOAuthPost(r.username(c), challenge, c)
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
		return c.Status(fiber.StatusInternalServerError).SendString(Translate("", "hydra.failed_to_accept_login"))
	}

	log.WithFields(log.Fields{
		"username": username,
	}).Debug("Hydra OAuth2 login POST challenge signed successfully")

	if c.Get("HX-Request", "false") == "true" {
		c.Set("HX-Redirect", *completedResponse.Payload.RedirectTo)
		return c.Status(fiber.StatusNoContent).SendString("")
	}

	return c.Redirect(*completedResponse.Payload.RedirectTo)
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

	return c.Status(fiber.StatusInternalServerError).SendString(Translate("", "hydra.oauth2_error"))
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
