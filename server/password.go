package server

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
)

var (
	PasswordCheckLower  = regexp.MustCompile(`[a-z]`)
	PasswordCheckUpper  = regexp.MustCompile(`[A-Z]`)
	PasswordCheckNumber = regexp.MustCompile(`[0-9]`)
	PasswordCheckMarks  = regexp.MustCompile(`[^0-9a-zA-Z]`)
)

// Simple password checker to validate passwords before creating an account
func checkPassword(pass string) error {
	minLength := viper.GetInt("min_passwd_len")
	minClasses := viper.GetInt("min_passwd_classes")

	l := len([]rune(pass))
	if l < minLength {
		return fmt.Errorf("Password does not conform to policy. Min length: %d", minLength)
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
		return fmt.Errorf("Password does not conform to policy. Min character classes required: %d", minClasses)
	}

	return nil
}

func validatePassword(password, passwordConfirm string) error {
	if password == "" {
		return errors.New("Please enter a new password")
	}

	if passwordConfirm == "" {
		return errors.New("Please confirm your new password")
	}

	if password != passwordConfirm {
		return errors.New("Password do not match. Please confirm your password.")
	}

	if err := checkPassword(password); err != nil {
		return err
	}

	return nil
}

func validatePasswordChange(passwordCurrent, password, passwordConfirm string) error {
	if passwordCurrent == "" {
		return errors.New("Please enter you current password")
	}

	if passwordCurrent == passwordConfirm {
		return errors.New("Current password is the same as new password. Please set a different password.")
	}

	return validatePassword(password, passwordConfirm)
}

func (r *Router) PasswordChange(c *fiber.Ctx) error {
	username := r.username(c)
	client := r.userClient(c)

	user, err := client.UserShow(username)
	if err != nil {
		return err
	}

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
		vars["message"] = "Please enter the 6-digit OTP code from your mobile app"
		return c.Render("password.html", vars)
	}

	if err := validatePasswordChange(password, newpass, newpass2); err != nil {
		vars["message"] = err.Error()
		return c.Render("password.html", vars)
	}

	err = client.ChangePassword(username, password, newpass, otp)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			log.WithFields(log.Fields{
				"username": username,
				"message":  ierr.Message,
				"code":     ierr.Code,
			}).Error("Failed to change password")
			vars["message"] = ierr.Message
		} else {
			log.WithFields(log.Fields{
				"username": username,
				"error":    err.Error(),
			}).Error("Failed to change password")
			vars["message"] = "Fatal system error"
		}
	} else {
		vars["success"] = true
	}

	return c.Render("password.html", vars)
}

func (r *Router) PasswordForgot(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodGet {
		vars := fiber.Map{
			"captchaID": captcha.New(),
		}

		return c.Render("password-forgot.html", vars)
	}

	err := r.verifyCaptcha(c.FormValue("captcha_id"), c.FormValue("captcha_sol"))
	if err != nil {
		c.Append("HX-Trigger", "{\"reloadCaptcha\":\""+captcha.New()+"\"}")
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	username := c.FormValue("username")

	user, err := r.adminClient.UserShow(username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Warn("Forgot password attempt for unknown username")
		return c.Render("password-forgot-success.html", fiber.Map{})
	}

	if user.Locked {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("Forgot password attempt for disabled/locked user")
		return c.Render("password-forgot-success.html", fiber.Map{})
	}

	// Send user a reset password email
	err = r.emailer.SendPasswordResetEmail(user, c.Get("User-Agent"))
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
	}

	return c.Render("password-forgot-success.html", fiber.Map{})
}

func (r *Router) PasswordReset(c *fiber.Ctx) error {
	token := c.Params("token")

	claims, err := model.ParseToken(token, viper.GetUint32("token_max_age"))
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	tokenUsed, err := r.storage.Get(token)
	if tokenUsed != nil {
		// Token already used
		log.WithFields(log.Fields{
			"username": claims.UserName,
			"email":    claims.Email,
		}).Warn("Attempt to re-use reset password token")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	user, err := r.adminClient.UserShow(claims.UserName)
	if err != nil {
		log.WithFields(log.Fields{
			"username": claims.UserName,
			"email":    claims.Email,
		}).Warn("Attempt to reset password for non-existent username")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	if user.Locked {
		log.WithFields(log.Fields{
			"username": claims.UserName,
			"email":    claims.Email,
		}).Warn("Attempt to reset password for disabled/locked user")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	if c.Method() == fiber.MethodGet {
		vars := fiber.Map{
			"claims": claims,
		}

		return c.Render("password-reset.html", vars)
	}

	password := c.FormValue("password")
	passwordConfirm := c.FormValue("password2")
	otp := c.FormValue("otpcode")

	if user.OTPOnly() && otp == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please enter the 6-digit OTP code from your mobile app")
	}

	if err := validatePassword(password, passwordConfirm); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	rand, err := r.adminClient.ResetPassword(user.Username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("System error please contact administrator")
	}

	err = r.adminClient.SetPassword(user.Username, rand, password, otp)
	if err != nil {
		switch {
		case errors.Is(err, ipa.ErrPasswordPolicy):
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err,
			}).Error("Password does not conform to policy")
			return c.Status(fiber.StatusBadRequest).SendString("Your password is too weak. Please ensure your password includes a number and lower/upper case character")
		case errors.Is(err, ipa.ErrInvalidPassword):
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err,
			}).Error("invalid password from FreeIPA")
			return c.Status(fiber.StatusBadRequest).SendString("Invalid OTP code.")
		default:
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err,
			}).Error("failed to set user password in FreeIPA")
			return c.Status(fiber.StatusInternalServerError).SendString("System error please contact administrator")
		}
	}

	r.storage.Set(token, []byte("true"), time.Until(time.Now().Add(time.Duration(viper.GetInt("token_max_age"))*time.Second)))

	return c.Render("password-reset-success.html", fiber.Map{})
}
