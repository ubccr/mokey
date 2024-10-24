package server

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	frecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/storage/memory/v2"
	"github.com/gofiber/storage/redis/v3"
	"github.com/gofiber/storage/sqlite3/v2"
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

func SetDefaults() {
	viper.SetDefault("site.name", "Acme Widgets")
	viper.SetDefault("site.ktuser", "mokeyapp")
	viper.SetDefault("accounts.hide_invalid_username_error", false)
	viper.SetDefault("accounts.default_homedir", "/home")
	viper.SetDefault("accounts.default_shell", "/bin/bash")
	viper.SetDefault("accounts.min_passwd_len", 8)
	viper.SetDefault("accounts.min_passwd_classes", 2)
	viper.SetDefault("accounts.otp_hash_algorithm", "sha1")
	viper.SetDefault("accounts.username_from_email", false)
	viper.SetDefault("accounts.require_mfa", false)
	viper.SetDefault("accounts.require_admin_verify", false)
	viper.SetDefault("email.token_max_age", 3600)
	viper.SetDefault("email.smtp_host", "localhost")
	viper.SetDefault("email.smtp_port", 25)
	viper.SetDefault("email.smtp_tls", "off")
	viper.SetDefault("email.from", "support@example.com")
	viper.SetDefault("server.secure_cookies", true)
	viper.SetDefault("server.session_idle_timeout", 900)
	viper.SetDefault("server.listen", "0.0.0.0:8866")
	viper.SetDefault("server.read_timeout", 5)
	viper.SetDefault("server.write_timeout", 5)
	viper.SetDefault("server.idle_timeout", 120)
	viper.SetDefault("server.rate_limit_expiration", 3600)
	viper.SetDefault("server.rate_limit_max", 10)
	viper.SetDefault("storage.driver", "memory")
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
	staticLocalPath := viper.GetString("site.static_assets_dir")
	if staticLocalPath != "" {
		log.Debugf("Using local static assets dir: %s", staticLocalPath)
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
		log.Errorf("Failed initialize storage driver %s: %s", viper.GetString("storage.driver"), r)
	}
}

func newStorage() fiber.Storage {
	var storage fiber.Storage

	if viper.IsSet("storage.sqlite3.dbpath") && viper.GetString("storage.driver") == "memory" {
		viper.Set("storage.driver", "sqlite3")
	}

	defer recoverInvalidStorage()
	switch viper.GetString("storage.driver") {
	case "sqlite3":
		storage = sqlite3.New(sqlite3.Config{
			Database: viper.GetString("storage.sqlite3.dbpath"),
			Table:    "mokey_data",
		})
	case "redis":
		storage = redis.New(redis.Config{
			URL:   viper.GetString("storage.redis.url"),
			Reset: false,
		})

	default:
		storage = memory.New()
	}

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
		ReadTimeout:           time.Duration(viper.GetInt("server.read_timeout")) * time.Second,
		WriteTimeout:          time.Duration(viper.GetInt("server.write_timeout")) * time.Second,
		IdleTimeout:           time.Duration(viper.GetInt("server.idle_timeout")) * time.Second,
		AppName:               "mokey",
		DisableStartupMessage: true,
		PassLocalsToViews:     true,
		ErrorHandler:          HTTPErrorHandler,
		Views:                 engine,
	})

	app.Use(frecover.New())
	app.Use(SecureHeaders)

	app.Use(limiter.New(limiter.Config{
		Max:                    viper.GetInt("server.rate_limit_max"),
		Expiration:             time.Duration(viper.GetInt("server.rate_limit_expiration")) * time.Second,
		SkipSuccessfulRequests: true,
		Storage:                storage,
		LimitReached:           LimitReachedHandler,
		KeyGenerator: func(c *fiber.Ctx) string {
			ips := c.IPs()
			if len(ips) > 0 {
				return ips[0]
			}

			return c.IP()
		},
		Next: func(c *fiber.Ctx) bool {
			if c.Method() != fiber.MethodPost {
				return true
			}

			if c.Path() == "/signup" {
				return false
			}

			if strings.HasPrefix(c.Path(), "/auth") {
				return false
			}

			return true
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
		MaxAge: 900,
	}))

	if viper.IsSet("site.favicon") {
		app.Use(favicon.New(favicon.Config{
			File: viper.GetString("site.favicon"),
		}))
	} else {
		app.Use(favicon.New(favicon.Config{
			File:       "images/favicon.ico",
			FileSystem: assetsFS,
		}))
	}

	// This must be last
	app.Use(NotFoundHandler)

	return app, nil
}

func (s *Server) Serve() error {
	if s.CertFile != "" && s.KeyFile != "" {
		s.Scheme = "https"
		log.Infof("Listening on %s://%s", s.Scheme, s.ListenAddress)
		if err := s.app.ListenTLS(s.ListenAddress, s.CertFile, s.KeyFile); err != nil {
			return err
		}
	}

	s.Scheme = "http"
	log.Infof("Listening on %s://%s", s.Scheme, s.ListenAddress)
	if err := s.app.Listen(s.ListenAddress); err != nil {
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
