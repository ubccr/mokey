package server

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	frecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/storage/sqlite3"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	DefaultPort = 80
)

//go:embed templates/static
var staticFS embed.FS

type Server struct {
	ListenAddress string
	Scheme        string
	KeyFile       string
	CertFile      string
	app           *fiber.App
}

func NewServer(address string) (*Server, error) {
	s := &Server{}
	s.ListenAddress = address

	app, err := newFiber()
	if err != nil {
		return nil, err
	}

	s.app = app

	return s, nil
}

func getAssetsFS() http.FileSystem {
	staticLocalPath := viper.GetString("static_assets_dir")
	if staticLocalPath != "" {
		log.Debug("Using local static assets dir: %s", staticLocalPath)
		return http.FS(os.DirFS(staticLocalPath))
	}

	fsys, err := fs.Sub(staticFS, "templates/static")
	if err != nil {
		log.Fatal(err)
	}

	return http.FS(fsys)
}

func recoverInvalidStorage() {
	if r := recover(); r != nil {
		log.Errorf("dbpath %s: %s", viper.GetString("dbpath"), r)
	}
}

func newStorage() fiber.Storage {
	defer recoverInvalidStorage()
	storage := sqlite3.New(sqlite3.Config{
		Database: viper.GetString("dbpath"),
		Table:    "mokey_data",
	})

	return storage
}

func newFiber() (*fiber.App, error) {
	engine, err := NewTemplateRenderer()
	if err != nil {
		log.Fatal(err)
	}

	storage := newStorage()
	if storage == nil {
		return nil, errors.New("Failed to open mokey storage database")
	}

	app := fiber.New(fiber.Config{
		Prefork:               false,
		CaseSensitive:         true,
		StrictRouting:         true,
		ReadTimeout:           5 * time.Second,
		WriteTimeout:          5 * time.Second,
		IdleTimeout:           120 * time.Second,
		AppName:               "mokey",
		DisableStartupMessage: false,
		PassLocalsToViews:     true,
		ErrorHandler:          HTTPErrorHandler,
		Views:                 engine,
	})

	app.Use(frecover.New())

	app.Use(csrf.New(csrf.Config{
		//KeyLookup: "form:csrf",
		KeyLookup:      "header:X-CSRF-Token",
		CookieName:     "csrf_",
		CookieSameSite: "Strict",
		Expiration:     1 * time.Hour,
		ContextKey:     "csrf",
		ErrorHandler:   CSRFErrorHandler,
		//Storage:        storage,
	}))

	app.Use(SecureHeaders)

	app.Use(limiter.New(limiter.Config{
		Max:                    15,
		Expiration:             1 * time.Minute,
		SkipSuccessfulRequests: false,
		Storage:                storage,
		LimitReached:           LimitReachedHandler,
		Next: func(c *fiber.Ctx) bool {
			// Only limit POST requests
			return c.Method() != "POST"
		},
	}))

	router, err := NewRouter(storage)
	if err != nil {
		return nil, err
	}

	router.SetupRoutes(app)

	assetsFS := getAssetsFS()
	app.Use("/static", filesystem.New(filesystem.Config{
		Root:   assetsFS,
		Browse: false,
	}))

	app.Use(favicon.New(favicon.Config{
		File:       "images/favicon.ico",
		FileSystem: assetsFS,
	}))

	// This must be last
	app.Use(NotFoundHandler)

	return app, nil
}

func (s *Server) Serve() error {
	if s.CertFile != "" && s.KeyFile != "" {
		s.Scheme = "https"
		log.Infof("Listening on %s://%s", s.Scheme, s.ListenAddress)
		if err := s.app.ListenTLS(":8080", s.CertFile, s.KeyFile); err != nil {
			return err
		}
	}

	s.Scheme = "http"
	log.Infof("Listening on %s://%s", s.Scheme, s.ListenAddress)
	if err := s.app.Listen(":8080"); err != nil {
		return err
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.app == nil {
		return nil
	}

	return s.app.Shutdown()
}
