package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ubccr/goipa"
)

func (r *Router) SecurityList(c *fiber.Ctx) error {
	username := c.Locals(ContextKeyUser).(string)
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)

	user, err := client.UserShow(username)
	if err != nil {
		return err
	}

	vars := fiber.Map{
		"user": user,
	}
	return c.Render("security.html", vars)
}
