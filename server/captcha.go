package server

import (
	"bytes"
	"net/http"
	"path"
	"time"

	"github.com/dchest/captcha"
	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
)

// Captcha handler displays captcha image
func (h *Handler) Captcha(c echo.Context) error {
	_, file := path.Split(c.Request().URL.Path)
	ext := path.Ext(file)
	id := file[:len(file)-len(ext)]
	if ext == "" || id == "" {
		return echo.NewHTTPError(http.StatusNotFound, "Captcha not found")
	}
	if c.Request().FormValue("reload") != "" {
		captcha.Reload(id)
	}

	c.Response().Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Response().Header().Set("Pragma", "no-cache")
	c.Response().Header().Set("Expires", "0")

	var content bytes.Buffer
	switch ext {
	case ".png":
		c.Response().Header().Set(echo.HeaderContentType, "image/png")
		err := captcha.WriteImage(&content, id, captcha.StdWidth, captcha.StdHeight)
		if err != nil {
			log.WithFields(log.Fields{
				"id": id,
			}).Warn("Captcha not found")
			return echo.NewHTTPError(http.StatusNotFound, "Captcha not found")
		}
	default:
		return echo.NewHTTPError(http.StatusNotFound, "Captcha not found")
	}

	http.ServeContent(c.Response(), c.Request(), id+ext, time.Time{}, bytes.NewReader(content.Bytes()))
	return nil
}
