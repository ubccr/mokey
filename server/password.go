package server

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/goipa"
)

func validatePassword(current, pass, pass2 string) error {
	if current == "" {
		return errors.New("Please enter you current password")
	}

	if pass == "" {
		return errors.New("Please enter a new password")
	}

	if pass2 == "" {
		return errors.New("Please confirm your new password")
	}

	if current == pass {
		return errors.New("Current password is the same as new password. Please set a different password.")
	}

	if pass != pass2 {
		return errors.New("Password do not match. Please confirm your password.")
	}

	return nil
}

func (r *Router) ChangePassword(c *fiber.Ctx) error {
	username := c.Locals(ContextKeyUser).(string)
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)

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

	if err := validatePassword(password, newpass, newpass2); err != nil {
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
