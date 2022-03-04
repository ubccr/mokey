// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
)

func SecureHeaders(c *fiber.Ctx) error {
	c.Set(fiber.HeaderXXSSProtection, "1; mode=block")
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
	c.Set(fiber.HeaderXFrameOptions, "DENY")
	c.Set(fiber.HeaderContentSecurityPolicy, "default-src 'self' 'unsafe-inline'; img-src 'self' data:;script-src 'self' 'unsafe-inline'")
	c.Set("Cache-Control", "no-store")
	c.Set("Pragma", "no-cache")
	return c.Next()
}

func NotFoundHandler(c *fiber.Ctx) error {
	log.WithFields(log.Fields{
		"path": c.Path(),
		"ip":   c.IP(),
	}).Info("Requested path not found")

	if c.Get("HX-Request", "false") == "true" {
		err := c.Render("404-partial.html", nil)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("Failed to render custom error partial")
			return c.Status(fiber.StatusNotFound).SendString("")
		}
		return nil
	}

	return c.Render("404.html", fiber.Map{})
}

func CSRFErrorHandler(c *fiber.Ctx, err error) error {
	log.WithFields(log.Fields{
		"path": c.Path(),
		"err":  err,
		"ip":   c.IP(),
	}).Error("Invalid CSRF token in POST request")

	return fiber.ErrForbidden
}

func HTTPErrorHandler(c *fiber.Ctx, err error) error {
	username := c.Locals(ContextKeyUser)
	path := c.Path()
	code := fiber.StatusInternalServerError

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	log.WithFields(log.Fields{
		"code":     code,
		"username": username,
		"path":     path,
		"ip":       c.IP(),
	}).Error(err)

	if c.Locals("NoErrorTemplate") == "true" {
		return c.Status(code).SendString("")
	}

	if c.Get("HX-Request", "false") == "true" {
		errorPage := fmt.Sprintf("%d-partial.html", code)
		err := c.Render(errorPage, nil)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("Failed to render custom error partial")
			return c.Status(code).SendString("")
		}
		return nil
	}

	errorPage := fmt.Sprintf("%d.html", code)
	err = c.Render(errorPage, nil)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to render custom error page")
		return c.Status(code).SendString("")
	}

	return nil
}

func LimitReachedHandler(c *fiber.Ctx) error {
	log.WithFields(log.Fields{
		"ip": c.IP(),
	}).Warn("Limit reached")
	return c.Status(fiber.StatusForbidden).SendString("Too many requests")
}

func (r *Router) RequireHTMX(c *fiber.Ctx) error {
	if c.Get("HX-Request", "false") == "true" {
		return c.Next()
	}

	return c.Status(fiber.StatusBadRequest).SendString("")
}
