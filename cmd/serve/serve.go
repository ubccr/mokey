package serve

import (
	"context"
	"os"
	"os/signal"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubccr/mokey/cmd"
	"github.com/ubccr/mokey/server"
)

var (
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Run server",
		Long:  `Run server`,
		RunE: func(command *cobra.Command, args []string) error {
			return serve()
		},
	}
)

func init() {
	serveCmd.Flags().String("listen", "0.0.0.0:80", "address to listen on")
	viper.BindPFlag("listen", serveCmd.Flags().Lookup("listen"))
	serveCmd.Flags().String("cert", "", "path to ssl cert")
	viper.BindPFlag("cert", serveCmd.Flags().Lookup("cert"))
	serveCmd.Flags().String("key", "", "path to ssl key")
	viper.BindPFlag("key", serveCmd.Flags().Lookup("key"))
	serveCmd.Flags().String("dbpath", "/var/mokey/mokey.db", "path to mokey database")
	viper.BindPFlag("dbpath", serveCmd.Flags().Lookup("dbpath"))

	cmd.Root.AddCommand(serveCmd)
}

func serve() error {
	srv, err := server.NewServer(viper.GetString("listen"))
	if err != nil {
		return err
	}

	srv.KeyFile = viper.GetString("key")
	srv.CertFile = viper.GetString("cert")

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt)
		<-quit
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		logrus.Debug("Shutting down server")
		srv.Shutdown(ctx)
	}()

	return srv.Serve()
}
