package server

import (
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/goipa"
)

func (r *Router) securityList(c *fiber.Ctx, vars fiber.Map) error {
	username := c.Locals(ContextKeyUser).(string)
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)

	user, err := client.UserShow(username)
	if err != nil {
		return err
	}

	vars["user"] = user
	return c.Render("security.html", vars)
}

func (r *Router) SecurityList(c *fiber.Ctx) error {
	return r.securityList(c, fiber.Map{})
}

func (r *Router) TwoFactorDisable(c *fiber.Ctx) error {
	username := c.Locals(ContextKeyUser).(string)
	vars := fiber.Map{}

	err := r.client.SetAuthTypes(username, nil)
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Error("Failed to disable Two-Factor auth")
		vars["message"] = "Failed to disable Two-Factor authentication"
	}

	return r.securityList(c, vars)
}

func (r *Router) TwoFactorEnable(c *fiber.Ctx) error {
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)
	username := c.Locals(ContextKeyUser).(string)
	vars := fiber.Map{}

	tokens, err := client.FetchOTPTokens(username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Error("Failed to check otp tokens")
		vars["message"] = "Failed to enable Two-Factor authentication"
		return r.securityList(c, vars)
	}

	if len(tokens) == 0 {
		vars["message"] = "You must add an OTP token first before enabling Two-Factor authentication"
		return r.securityList(c, vars)
	}

	err = r.client.SetAuthTypes(username, []string{"otp"})
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Error("Failed to enable Two-Factor auth")
		vars["message"] = "Failed to enable Two-Factor authentication"
	}

	return r.securityList(c, vars)
}
