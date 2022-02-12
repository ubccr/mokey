package server

import (
	"net/http"
	"strings"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/util"
)

func (h *Handler) OTPTokensOld(c echo.Context) error {
	user := c.Get(ContextKeyUser).(*ipa.UserRecord)
	client := c.Get(ContextKeyIPAClient).(*ipa.Client)

	sess, err := session.Get(CookieKeySession, c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session")
	}

	tokens, err := client.FetchOTPTokens(string(user.Uid))
	if err != nil {
		log.WithFields(log.Fields{
			"user":  string(user.Uid),
			"error": err,
		}).Error("failed to fetch OTP Tokens")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch otp tokens")
	}

	vars := map[string]interface{}{
		"user":      user,
		"flashes":   sess.Flashes(),
		"otptokens": tokens,
		"csrf":      c.Get("csrf").(string),
	}

	return c.Render(http.StatusOK, "otp-tokens.html", vars)
}

func (h *Handler) ModifyOTPTokens(c echo.Context) error {
	user := c.Get(ContextKeyUser).(*ipa.UserRecord)
	client := c.Get(ContextKeyIPAClient).(*ipa.Client)

	vars := map[string]interface{}{
		"user": user,
		"csrf": c.Get("csrf").(string),
	}

	action := c.FormValue("action")
	uuid := c.FormValue("uuid")
	log.WithFields(log.Fields{
		"user":   string(user.Uid),
		"uuid":   uuid,
		"action": action,
	}).Info("otptokens action")

	if action == "delete" && len(uuid) > 0 {
		err := client.RemoveOTPToken(uuid)
		if err != nil {
			log.WithFields(log.Fields{
				"user":  string(user.Uid),
				"uuid":  uuid,
				"error": err,
			}).Error("failed to remove OTP Token")

			// Raised when there's an operations error
			if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4203 && strings.Contains(ierr.Message, "last active token") {
				vars["message"] = "Can't delete last active token"
			} else {
				vars["message"] = "Failed to remove OTP Token"
			}
		}
	} else if action == "enable" && len(uuid) > 0 {
		err := client.EnableOTPToken(uuid)
		if err != nil {
			log.WithFields(log.Fields{
				"user":  string(user.Uid),
				"uuid":  uuid,
				"error": err,
			}).Error("failed to enable OTP Token")
			vars["message"] = "Failed to enable OTP Token"
		}
	} else if action == "disable" && len(uuid) > 0 {
		err := client.DisableOTPToken(uuid)
		if err != nil {
			log.WithFields(log.Fields{
				"user":  string(user.Uid),
				"uuid":  uuid,
				"error": err,
			}).Error("failed to disable OTP Token")
			vars["message"] = "Failed to disable OTP Token"
		}
	} else if action == "add" {
		return h.addNewToken(c)
	}

	tokens, err := client.FetchOTPTokens(string(user.Uid))
	if err != nil {
		log.WithFields(log.Fields{
			"user":  string(user.Uid),
			"error": err,
		}).Error("failed to fetch OTP Tokens")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch otp tokens")
	}

	vars["otptokens"] = tokens

	return c.Render(http.StatusOK, "otp-tokens.html", vars)
}

func (h *Handler) TwoFactorAuth(c echo.Context) error {
	user := c.Get(ContextKeyUser).(*ipa.UserRecord)
	client := c.Get(ContextKeyIPAClient).(*ipa.Client)

	vars := map[string]interface{}{
		"user": user,
		"csrf": c.Get("csrf").(string),
	}

	if c.Request().Method == "POST" {
		// These operations require admin privs. TODO: should we make this
		// configurable?
		action := c.FormValue("action")
		if action == "remove" {
			// Remove any auth types which will fall back to FreeIPA global default.
			err := h.client.SetAuthTypes(string(user.Uid), nil)
			if err == nil {
				user.AuthTypes = []string{}
			} else {
				log.WithFields(log.Fields{
					"user":  string(user.Uid),
					"error": err,
				}).Error("failed to reset auth types to default")
				vars["message"] = "Failed to disable TOTP. Please contact your administrator"
			}
		} else if action == "enable" {
			err := h.client.SetAuthTypes(string(user.Uid), []string{"otp"})
			if err == nil {
				user.AuthTypes = []string{"otp"}
			} else {
				log.WithFields(log.Fields{
					"user":  string(user.Uid),
					"error": err,
				}).Error("failed to set auth types to otp")
				vars["message"] = "Failed to enable TOTP. Please contact your administrator"
			}

			tokens, err := client.FetchOTPTokens(string(user.Uid))
			if err != nil {
				log.WithFields(log.Fields{
					"user":  string(user.Uid),
					"error": err,
				}).Error("failed to fetch OTP tokens")
				return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch otp tokens")
			}
			if len(tokens) == 0 {
				return h.addNewToken(c)
			}
		}
	}

	vars["otpenabled"] = user.OTPOnly()
	return c.Render(http.StatusOK, "2fa.html", vars)
}

func (h *Handler) addNewToken(c echo.Context) error {
	user := c.Get(ContextKeyUser).(*ipa.UserRecord)
	client := c.Get(ContextKeyIPAClient).(*ipa.Client)

	otptoken, err := client.AddTOTPToken(string(user.Uid), ipa.AlgorithmSHA1, ipa.DigitsSix, 30)
	if err != nil {
		log.WithFields(log.Fields{
			"user":  string(user.Uid),
			"error": err,
		}).Error("Failed to create TOTP")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create TOTP")
	}

	otpdata, err := util.QRCode(otptoken)
	if err != nil {
		log.WithFields(log.Fields{
			"user":  string(user.Uid),
			"error": err,
		}).Error("failed to render TOTP token as QRCode image")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to render qrcode")
	}

	vars := map[string]interface{}{
		"otpdata":  otpdata,
		"otptoken": otptoken,
		"user":     user}

	return c.Render(http.StatusOK, "verify-totp.html", vars)
}
