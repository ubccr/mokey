package server

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	ipa "github.com/ubccr/goipa"
)

var (
	PasswordCheckLower  = regexp.MustCompile(`[a-z]`)
	PasswordCheckUpper  = regexp.MustCompile(`[A-Z]`)
	PasswordCheckNumber = regexp.MustCompile(`[0-9]`)
	PasswordCheckMarks  = regexp.MustCompile(`[^0-9a-zA-Z]`)
)

// Simple password checker to validate passwords before creating an account
func checkPassword(pass string) error {
	minLength := viper.GetInt("accounts.min_passwd_len")
	minClasses := viper.GetInt("accounts.min_passwd_classes")

	l := len([]rune(pass))
	if l < minLength {
	    // Translators: “Min length: %d” – keep the placeholder for the length
	    return fmt.Errorf(Translate("", "password.min_length"), minLength)
	}

	numCategories := 0

	if PasswordCheckLower.MatchString(pass) {
		numCategories++
	}
	if PasswordCheckUpper.MatchString(pass) {
		numCategories++
	}
	if PasswordCheckNumber.MatchString(pass) {
		numCategories++
	}
	if PasswordCheckMarks.MatchString(pass) {
		numCategories++
	}

	repeated := 0
	for i := 0; i < l; i++ {
		count := 1
		for j := i + 1; j < l; j++ {
			if pass[i] != pass[j] {
				break
			}
			count++
		}

		if count > repeated {
			repeated = count
		}
	}

	if repeated > 1 {
		numCategories--
	}

	if numCategories < minClasses {
		// Translators: “Password does not conform to policy…” – generic message
		return fmt.Errorf(Translate("", "password.policy_not_met"))
	}

	return nil
}

func validatePassword(password, passwordConfirm string) error {
	if password == "" {
		// Translators: Prompt user to enter a new password
		return errors.New(Translate("", "password.enter_new"))
	}

	if passwordConfirm == "" {
		// Translators: Prompt user to confirm the new password
		return errors.New(Translate("", "password.confirm_new"))
	}

	if password != passwordConfirm {
		// Translators: Prompt user to confirm the new password
		return errors.New(Translate("", "password.confirm_new"))
	}

	if err := checkPassword(password); err != nil {
		return err
	}

	return nil
}

func validatePasswordChange(passwordCurrent, password, passwordConfirm string) error {
	if passwordCurrent == "" {
		// Translators: Prompt user to enter current password
		return errors.New(Translate("", "password.enter_current"))
	}

	if passwordCurrent == passwordConfirm {
		// Translators: Current password equals new password
		return errors.New(Translate("", "password.same_as_new"))
	}

	return validatePassword(password, passwordConfirm)
}

func (r *Router) PasswordChange(c *fiber.Ctx) error {
	user := r.user(c)
	client := r.userClient(c)

	vars := fiber.Map{
		"user": user,
	}

	if c.Method() == fiber.MethodGet {
		return c.Render("password.html", vars)
	}

	password := c.FormValue("password")
	newpass := c.FormValue("newpassword")
	newpass2 := c.FormValue("newpassword2")
	otp := c.FormValue("otpcode")

	if user.OTPOnly() && otp == "" {
		// Translators: OTP prompt for users that only use OTP
		vars["message"] = Translate("", "password_change.otp_help")
		return c.Render("password.html", vars)
	}

	if err := validatePasswordChange(password, newpass, newpass2); err != nil {
		vars["message"] = err.Error()
		return c.Render("password.html", vars)
	}

	err := client.ChangePassword(user.Username, password, newpass, otp)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			log.WithFields(log.Fields{
				"username": user.Username,
				"message":  ierr.Message,
				"code":     ierr.Code,
			}).Error("Failed to change password")
			vars["message"] = ierr.Message
		} else {
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err.Error(),
			}).Error("Failed to change password")
			vars["message"] = Translate("", "account.system_error")
		}
	} else {
		err = r.emailer.SendPasswordChangedEmail(user, c)
		if err != nil {
			log.WithFields(log.Fields{
				"err":      err,
				"username": user.Username,
				"email":    user.Email,
			}).Error("Failed to send password changed email")
		}

		vars["success"] = true
	}

	return c.Render("password.html", vars)
}

func (r *Router) PasswordForgot(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodGet {
		vars := fiber.Map{
			"captchaID": captcha.New(),
		}
		if username := strings.TrimSpace(c.Query("username")); username != "" {
			vars["username"] = username
		}
		if c.Query("expired") == "1" {
			vars["message"] = Translate("", "password_forgot.expired_redirect")
		}

		return c.Render("password-forgot.html", vars)
	}

	err := r.verifyCaptcha(c.FormValue("captcha_id"), c.FormValue("captcha_sol"))
	if err != nil {
		c.Append("HX-Trigger", "{\"reloadCaptcha\":\""+captcha.New()+"\"}")
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	username := c.FormValue("username")

	if isBlocked(username) {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("AUDIT Forgot password attempt for blocked username")
		return c.Render("password-forgot-success.html", fiber.Map{})
	}

	user, err := r.adminClient.UserShow(username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Warn("AUDIT Forgot password attempt for unknown username")
		return c.Render("password-forgot-success.html", fiber.Map{})
	}

	if user.Locked {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("AUDIT Forgot password attempt for disabled/locked user")
		return c.Render("password-forgot-success.html", fiber.Map{})
	}

	// Send user a reset password email
	err = r.emailer.SendPasswordResetEmail(user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to send reset password email")
	} else {
		log.WithFields(log.Fields{
			"username": user.Username,
			"email":    user.Email,
		}).Info("Password reset email sent successfully")
		r.metrics.totalPasswordResetsSent.Inc()
	}

	return c.Render("password-forgot-success.html", fiber.Map{})
}

func (r *Router) PasswordReset(c *fiber.Ctx) error {
	token := c.Params("token")

	claims, err := ParseToken(token, TokenPasswordReset, r.storage)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	user, err := r.adminClient.UserShow(claims.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": claims.Username,
			"email":    claims.Email,
		}).Warn("Attempt to reset password for non-existent username")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	if user.Locked {
		log.WithFields(log.Fields{
			"username": claims.Username,
			"email":    claims.Email,
		}).Warn("AUDIT Attempt to reset password for disabled/locked user")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	if c.Method() == fiber.MethodGet {
		vars := fiber.Map{
			"claims": claims,
			"user":   user,
		}

		return c.Render("password-reset.html", vars)
	}

	password := c.FormValue("password")
	passwordConfirm := c.FormValue("password2")
	otp := c.FormValue("otpcode")

	if user.OTPOnly() && otp == "" {
		return c.Status(fiber.StatusBadRequest).SendString(Translate("", "password_change.otp_help"))
	}

	if err := validatePassword(password, passwordConfirm); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	rand, err := r.adminClient.ResetPassword(user.Username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(Translate("", "account.system_error"))
	}

	err = r.adminClient.SetPassword(user.Username, rand, password, otp)
	if err != nil {
		switch {
		case errors.Is(err, ipa.ErrPasswordPolicy):
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err,
			}).Error("Password does not conform to policy")
			return c.Status(fiber.StatusBadRequest).SendString(Translate("", "account.weak_password"))
		case errors.Is(err, ipa.ErrInvalidPassword):
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err,
			}).Error("invalid password from FreeIPA")
			return c.Status(fiber.StatusBadRequest).SendString(Translate("", "otptoken.invalid_otp"))
		default:
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err,
			}).Error("failed to set user password in FreeIPA")
			return c.Status(fiber.StatusInternalServerError).SendString(Translate("", "account.system_error"))
		}
	}

	r.storage.Set(TokenPasswordReset+TokenUsedPrefix+token, []byte("true"), time.Until(claims.Timestamp.Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second)))

	err = r.emailer.SendPasswordChangedEmail(user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to send password changed email")
	}

	log.WithFields(log.Fields{
		"username": user.Username,
	}).Info("AUDIT User password changed successfully")
	r.metrics.totalPasswordResets.Inc()

	return c.Render("password-reset-success.html", fiber.Map{})
}

// PasswordExpiredRedirect sends legacy expired-password URLs to the forgot-password flow.
func (r *Router) PasswordExpiredRedirect(c *fiber.Ctx) error {
	target := "/auth/forgotpw?expired=1"
	if username := strings.TrimSpace(c.FormValue("username")); username != "" {
		target = fmt.Sprintf("/auth/forgotpw?expired=1&username=%s", url.QueryEscape(username))
	}
	return c.Redirect(target)
}
