package server

import (
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/goipa"
)

func (r *Router) AccountSettings(c *fiber.Ctx) error {
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
		return c.Render("account.html", vars)
	}

	user.First = c.FormValue("first")
	user.Last = c.FormValue("last")
	user.Mobile = c.FormValue("phone")

	userUpdated, err := client.UserMod(user)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			log.WithFields(log.Fields{
				"username": username,
				"message":  ierr.Message,
				"code":     ierr.Code,
			}).Error("Failed to update account settings")
			vars["message"] = ierr.Message
		} else {
			log.WithFields(log.Fields{
				"username": username,
				"error":    err.Error(),
			}).Error("Failed to update account settings")
			vars["message"] = "Fatal system error"
		}
	} else {
		vars["user"] = userUpdated
		vars["success"] = true
	}
	return c.Render("account.html", vars)
}
