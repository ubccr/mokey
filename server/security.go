package server

import (
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
)

func (r *Router) securityList(c *fiber.Ctx, vars fiber.Map) error {
	vars["user"] = r.user(c)
	return c.Render("security.html", vars)
}

func (r *Router) SecurityList(c *fiber.Ctx) error {
	return r.securityList(c, fiber.Map{})
}

func (r *Router) TwoFactorDisable(c *fiber.Ctx) error {
	vars := fiber.Map{}
	user := r.user(c)

	err := r.adminClient.SetAuthTypes(user.Username, nil)
	if err != nil {
		log.WithFields(log.Fields{
			"username": user.Username,
			"err":      err,
		}).Error("Failed to disable Two-Factor auth")
		vars["message"] = "Failed to disable Two-Factor authentication"
	}

	user.AuthTypes = nil
	c.Locals(ContextKeyUser, user)

	err = r.emailer.SendMFAChangedEmail(false, user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
		}).Error("Failed to send mfa disabled email")
	}

	return r.securityList(c, vars)
}

func (r *Router) TwoFactorEnable(c *fiber.Ctx) error {
	client := r.userClient(c)
	vars := fiber.Map{}
	user := r.user(c)

	tokens, err := client.FetchOTPTokens(user.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": user.Username,
			"err":      err,
		}).Error("Failed to check otp tokens")
		vars["message"] = "Failed to enable Two-Factor authentication"
		return r.securityList(c, vars)
	}

	if len(tokens) == 0 {
		vars["message"] = "You must add an OTP token first before enabling Two-Factor authentication"
		return r.securityList(c, vars)
	}

	otpOnly := []string{"otp"}
	err = r.adminClient.SetAuthTypes(user.Username, otpOnly)
	if err != nil {
		log.WithFields(log.Fields{
			"username": user.Username,
			"err":      err,
		}).Error("Failed to enable Two-Factor auth")
		vars["message"] = "Failed to enable Two-Factor authentication"
	}

	user.AuthTypes = otpOnly
	c.Locals(ContextKeyUser, user)

	err = r.emailer.SendMFAChangedEmail(true, user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
		}).Error("Failed to send mfa enabled email")
	}

	return r.securityList(c, vars)
}
