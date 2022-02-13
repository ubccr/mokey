package server

import (
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	DefaultPort = 80
)

//go:embed templates/static
var staticFiles embed.FS

type Server struct {
	ListenAddress net.IP
	Port          int
	Scheme        string
	KeyFile       string
	CertFile      string
	httpServer    *http.Server
}

func NewServer(address string) (*Server, error) {
	s := &Server{}

	shost, sport, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	if shost == "" {
		shost = net.IPv4zero.String()
	}

	port := DefaultPort
	if sport != "" {
		var err error
		port, err = strconv.Atoi(sport)
		if err != nil {
			return nil, err
		}
	}

	s.Port = port

	ip := net.ParseIP(shost)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("Invalid IPv4 address: %s", shost)
	}

	s.ListenAddress = ip

	return s, nil
}

func getAssetsFS() http.FileSystem {
	staticLocalPath := viper.GetString("static_assets_dir")
	if staticLocalPath != "" {
		log.Debug("Using local static assets dir: %s", staticLocalPath)
		return http.FS(os.DirFS(staticLocalPath))
	}

	fsys, err := fs.Sub(staticFiles, "templates/static")
	if err != nil {
		log.Fatal(err)
	}

	return http.FS(fsys)
}

func newEcho() (*echo.Echo, error) {
	e := echo.New()
	e.HTTPErrorHandler = HTTPErrorHandler
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Logger = EchoLogger()

	assetHandler := http.FileServer(getAssetsFS())
	e.GET("/static/*", echo.WrapHandler(http.StripPrefix("/static/", assetHandler)))

	e.Use(CacheControl)
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup:    "form:csrf",
		CookieSecure:   !viper.GetBool("develop"),
		CookieHTTPOnly: true,
	}))
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XFrameOptions:         "DENY",
		ContentSecurityPolicy: "default-src 'self' 'unsafe-inline'; img-src 'self' data:;script-src 'self' 'unsafe-inline';",
	}))

	renderer, err := NewTemplateRenderer()
	if err != nil {
		return nil, err
	}

	e.Renderer = renderer

	return e, nil
}

func HTTPErrorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}

	path := c.Request().URL.Path
	code := http.StatusInternalServerError

	if he, ok := err.(*echo.HTTPError); ok {
		if he.Code == http.StatusNotFound {
			log.WithFields(log.Fields{
				"path": path,
				"ip":   c.RealIP(),
			}).Info("Requested path not found")
		} else {
			log.WithFields(log.Fields{
				"code": he.Code,
				"err":  he.Internal,
				"path": path,
				"ip":   c.RealIP(),
			}).Error(he.Message)
		}
		code = he.Code
	} else {
		log.WithFields(log.Fields{
			"err":  err,
			"path": path,
			"ip":   c.RealIP(),
		}).Error("HTTP Error")
	}

	errorPage := fmt.Sprintf("%d.html", code)
	if err := c.Render(code, errorPage, nil); err != nil {
		c.Logger().Error(err)
		c.String(code, "")
	}
}

func (s *Server) Serve() error {
	e, err := newEcho()
	if err != nil {
		return err
	}

	h, err := NewHandler()
	if err != nil {
		return err
	}

	h.SetupRoutes(e)

	httpServer := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.ListenAddress, s.Port),
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 15 * time.Minute,
		IdleTimeout:  120 * time.Second,
	}

	if s.CertFile != "" && s.KeyFile != "" {
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		httpServer.TLSConfig = cfg
		httpServer.TLSConfig.Certificates = make([]tls.Certificate, 1)
		httpServer.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return err
		}

		s.Scheme = "https"
		httpServer.Addr = fmt.Sprintf("%s:%d", s.ListenAddress, s.Port)
	} else {
		s.Scheme = "http"
	}

	s.httpServer = httpServer
	log.Infof("Listening on %s://%s:%d", s.Scheme, s.ListenAddress, s.Port)
	if err := e.StartServer(httpServer); err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}

	return s.httpServer.Shutdown(ctx)
}
