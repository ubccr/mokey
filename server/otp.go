package server

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/util"
)

func (r *Router) OTPTokenList(c *fiber.Ctx) error {
	username := c.Locals(ContextKeyUser).(string)
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)

	tokens, err := client.FetchOTPTokens(username)
	if err != nil {
		return err
	}

	vars := fiber.Map{
		"otptokens": tokens,
	}
	return c.Render("otptoken-list.html", vars)
}

func (r *Router) OTPTokenModal(c *fiber.Ctx) error {
	vars := fiber.Map{}
	return c.Render("otptoken-new.html", vars)
}

func (r *Router) OTPTokenAdd(c *fiber.Ctx) error {
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)

	desc := c.FormValue("desc")

	token := &ipa.OTPToken{
		Type:        ipa.TokenTypeTOTP,
		Algorithm:   ipa.AlgorithmSHA256,
		Description: desc,
		NotBefore:   time.Now(),
	}

	token, err := client.AddOTPToken(
		&ipa.OTPToken{
			Type:        ipa.TokenTypeTOTP,
			Algorithm:   ipa.AlgorithmSHA256,
			Description: desc,
			NotBefore:   time.Now(),
		})

	if err != nil {
		return err
	}

	otpdata, err := util.QRCode(token)
	if err != nil {
		return err
	}

	vars := fiber.Map{
		"otpdata": otpdata,
	}
	return c.Render("otptoken-scan.html", vars)
}
