package server

import (
	"github.com/gofiber/fiber/v2"
)

func (r *Router) AccountInfo(c *fiber.Ctx) error {
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

	return c.Render("account.html", vars)
}
