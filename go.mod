module github.com/ubccr/mokey

require (
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/dchest/captcha v1.0.0 // indirect
	github.com/dustin/go-humanize v1.0.0
	github.com/eknkc/basex v1.0.1 // indirect
	github.com/go-ini/ini v1.66.3 // indirect
	github.com/go-sql-driver/mysql v1.6.0
	github.com/gofiber/fiber/v2 v2.26.0
	github.com/gofiber/storage/sqlite3 v0.0.0-20220210144513-cc5ccf062b5d
	github.com/gorilla/mux v1.8.0
	github.com/hako/branca v0.0.0-20200807062402-6052ac720505
	github.com/jmoiron/sqlx v1.3.4
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mileusna/useragent v1.2.0 // indirect
	github.com/pkg/errors v0.9.1
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/pquerna/otp v1.3.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/afero v1.8.1 // indirect
	github.com/spf13/cobra v1.3.0
	github.com/spf13/viper v1.10.1
	github.com/stretchr/testify v1.7.0
	github.com/ubccr/goipa v0.0.5
	github.com/urfave/negroni v1.0.0
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd // indirect
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8
	golang.org/x/sys v0.0.0-20220207234003-57398862261d // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)

replace github.com/ubccr/goipa => /home/centos/projects/goipa

go 1.16
