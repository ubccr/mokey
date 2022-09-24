package server

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/util"
)

func (r *Router) tokenList(c *fiber.Ctx, vars fiber.Map) error {
	username := c.Locals(ContextKeyUser).(string)
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)

	tokens, err := client.FetchOTPTokens(username)
	if err != nil {
		return err
	}

	vars["otptokens"] = tokens
	return c.Render("otptoken-list.html", vars)
}

func (r *Router) OTPTokenList(c *fiber.Ctx) error {
	return r.tokenList(c, fiber.Map{})
}

func (r *Router) OTPTokenModal(c *fiber.Ctx) error {
	vars := fiber.Map{}
	return c.Render("otptoken-new.html", vars)
}

func (r *Router) OTPTokenRemove(c *fiber.Ctx) error {
	uuid := c.FormValue("uuid")
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)
	username := c.Locals(ContextKeyUser).(string)
	vars := fiber.Map{}

	err := client.RemoveOTPToken(uuid)
	if err != nil {
		log.WithFields(log.Fields{
			"uuid":     uuid,
			"username": username,
			"err":      err,
		}).Error("Failed to delete OTP token")
		vars["message"] = "Failed to remove token"
	}

	return r.tokenList(c, vars)
}

func (r *Router) OTPTokenEnable(c *fiber.Ctx) error {
	uuid := c.FormValue("uuid")
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)
	username := c.Locals(ContextKeyUser).(string)
	vars := fiber.Map{}

	err := client.EnableOTPToken(uuid)
	if err != nil {
		log.WithFields(log.Fields{
			"uuid":     uuid,
			"username": username,
			"err":      err,
		}).Error("Failed to enable OTP token")
		vars["message"] = "Failed to enable token"
	}

	return r.tokenList(c, vars)
}

func (r *Router) OTPTokenDisable(c *fiber.Ctx) error {
	uuid := c.FormValue("uuid")
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)
	username := c.Locals(ContextKeyUser).(string)
	vars := fiber.Map{}

	err := client.DisableOTPToken(uuid)
	if err != nil {
		log.WithFields(log.Fields{
			"uuid":     uuid,
			"username": username,
			"err":      err,
		}).Error("Failed to disable OTP token")
		vars["message"] = "Failed to disable token"
	}

	return r.tokenList(c, vars)
}

func (r *Router) OTPTokenVerify(c *fiber.Ctx) error {
	otpcode := c.FormValue("otpcode")
	uri := c.FormValue("uri")
	uuid := c.FormValue("uuid")
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)
	username := c.Locals(ContextKeyUser).(string)
	vars := fiber.Map{}

	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		client.RemoveOTPToken(uuid)
		vars["message"] = "Failed to verify token. Invalid 6-digit code."
		return r.tokenList(c, vars)
	}

	valid, _ := totp.ValidateCustom(
		otpcode,
		key.Secret(),
		time.Now().UTC(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA256,
		},
	)
	if !valid {
		client.RemoveOTPToken(uuid)
		log.WithFields(log.Fields{
			"uuid":     uuid,
			"username": username,
		}).Error("Failed to verify OTP token")
		vars["message"] = "Failed to verify token. Invalid 6-digit code."
	}

	return r.tokenList(c, vars)
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

	otpdata, err := util.QRCode(token, client.Realm())
	if err != nil {
		return err
	}

	vars := fiber.Map{
		"otpdata":  otpdata,
		"otptoken": token,
	}
	return c.Render("otptoken-scan.html", vars)
}
