module github.com/ubccr/mokey

require (
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/census-instrumentation/opencensus-proto v0.3.0 // indirect
	github.com/cncf/xds/go v0.0.0-20211130200136-a8f946100490 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/dchest/captcha v1.0.0
	github.com/dustin/go-humanize v1.0.0
	github.com/envoyproxy/protoc-gen-validate v0.6.2 // indirect
	github.com/essentialkaos/branca v1.3.2
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/gofiber/fiber/v2 v2.38.1
	github.com/gofiber/storage/memory v0.0.0-20220921084501-87862b1ac6ad
	github.com/gofiber/storage/redis v0.0.0-20220921084501-87862b1ac6ad
	github.com/gofiber/storage/sqlite3 v0.0.0-20220921084501-87862b1ac6ad
	github.com/gorilla/mux v1.8.0
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.3 // indirect
	github.com/klauspost/compress v1.15.11 // indirect
	github.com/mileusna/useragent v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/pquerna/otp v1.3.0
	github.com/sirupsen/logrus v1.9.0
	github.com/spf13/afero v1.9.2 // indirect
	github.com/spf13/cobra v1.5.0
	github.com/spf13/viper v1.13.0
	github.com/stretchr/testify v1.8.0
	github.com/tidwall/gjson v1.14.3 // indirect
	github.com/ubccr/goipa v0.0.5
	github.com/urfave/negroni v1.0.0
	golang.org/x/crypto v0.0.0-20220926161630-eccd6366d1be // indirect
	golang.org/x/net v0.0.0-20220927171203-f486391704dc // indirect
	golang.org/x/oauth2 v0.0.0-20220411215720-9780585627b5
	golang.org/x/sys v0.0.0-20220928140112-f11e5e49a4ec // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)

replace github.com/ubccr/goipa => /home/centos/projects/goipa

go 1.16
