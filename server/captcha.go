package server

import (
	"bytes"

	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
)

// Captcha handler displays captcha image
func (r *Router) Captcha(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	if c.FormValue("reload") != "" {
		captcha.Reload(id)
	}

	c.Append("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Append("Pragma", "no-cache")
	c.Append("Expires", "0")

	var content bytes.Buffer
	c.Append(fiber.HeaderContentType, "image/png")
	err := captcha.WriteImage(&content, id, captcha.StdWidth, captcha.StdHeight)
	if err != nil {
		log.WithFields(log.Fields{
			"id": id,
		}).Warn("Captcha not found")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	return c.SendStream(bytes.NewReader(content.Bytes()))
}
