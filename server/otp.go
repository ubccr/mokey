package server

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
)

func getHashAlgorithm() otp.Algorithm {
	algo := viper.GetString("accounts.otp_hash_algorithm")
	switch algo {
	case "sha256":
		return otp.AlgorithmSHA256
	case "sha512":
		return otp.AlgorithmSHA512
	default:
		return otp.AlgorithmSHA1
	}
}

func (r *Router) tokenList(c *fiber.Ctx, vars fiber.Map) error {
	username := r.username(c)
	client := r.userClient(c)

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
	client := r.userClient(c)
	username := r.username(c)
	vars := fiber.Map{}

	err := client.RemoveOTPToken(uuid)
	if err != nil {
		log.WithFields(log.Fields{
			"uuid":     uuid,
			"username": username,
			"err":      err,
		}).Error("Failed to remove OTP token")

		if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4203 {
			vars["message"] = "You can't remove your last active token while Two-Factor auth is enabled"
		} else {
			vars["message"] = "Failed to remove token"
		}
	}

	return r.tokenList(c, vars)
}

func (r *Router) OTPTokenEnable(c *fiber.Ctx) error {
	uuid := c.FormValue("uuid")
	client := r.userClient(c)
	username := r.username(c)
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
	client := r.userClient(c)
	username := r.username(c)
	vars := fiber.Map{}

	err := client.DisableOTPToken(uuid)
	if err != nil {
		log.WithFields(log.Fields{
			"uuid":     uuid,
			"username": username,
			"err":      err,
		}).Error("Failed to enable OTP token")

		if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4203 {
			vars["message"] = "You can't disable your last active token while Two-Factor auth is enabled"
		} else {
			vars["message"] = "Failed to disable token"
		}
	}

	return r.tokenList(c, vars)
}

func (r *Router) OTPTokenVerify(c *fiber.Ctx) error {
	otpcode := c.FormValue("otpcode")
	uri := c.FormValue("uri")
	uuid := c.FormValue("uuid")
	action := c.FormValue("action")
	client := r.userClient(c)
	username := r.username(c)
	vars := fiber.Map{}

	key, err := otp.NewKeyFromURL(uri)
	if err != nil || action == "cancel" {
		client.RemoveOTPToken(uuid)
		vars["message"] = "Failed to verify token."
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
			Algorithm: getHashAlgorithm(),
		},
	)
	if !valid {
		log.WithFields(log.Fields{
			"uuid":     uuid,
			"username": username,
		}).Error("Failed to verify OTP token")
		return c.Status(fiber.StatusBadRequest).SendString("Invalid 6-digit code. Please try again.")
	}

	return r.tokenList(c, vars)
}

func (r *Router) OTPTokenAdd(c *fiber.Ctx) error {
	client := r.userClient(c)

	desc := c.FormValue("desc")

	token := &ipa.OTPToken{
		Type:        ipa.TokenTypeTOTP,
		Algorithm:   strings.ToLower(getHashAlgorithm().String()),
		Description: desc,
		NotBefore:   time.Now(),
	}

	token, err := client.AddOTPToken(
		&ipa.OTPToken{
			Type:        ipa.TokenTypeTOTP,
			Algorithm:   strings.ToLower(getHashAlgorithm().String()),
			Description: desc,
			NotBefore:   time.Now(),
		})

	if err != nil {
		return err
	}

	otpdata, err := QRCode(token, client.Realm())
	if err != nil {
		return err
	}

	vars := fiber.Map{
		"otpdata":  otpdata,
		"otptoken": token,
	}
	return c.Render("otptoken-scan.html", vars)
}
