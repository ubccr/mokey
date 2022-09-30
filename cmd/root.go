package cmd

import (
	"io/ioutil"
	golog "log"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubccr/mokey/server"
)

var (
	cfgFile     string
	cfgFileUsed string
	trace       bool
	debug       bool
	verbose     bool

	Root = &cobra.Command{
		Use:     "mokey",
		Version: server.Version,
		Short:   "FreeIPA self-service account management tool",
		Long:    ``,
	}
)

func Execute() {
	if err := Root.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	Root.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
	Root.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug messages")
	Root.PersistentFlags().BoolVar(&trace, "trace", false, "Enable trace messages")
	Root.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose messages")

	Root.PersistentPreRunE = func(command *cobra.Command, args []string) error {
		return SetupLogging()
	}
}

func SetupLogging() error {
	if trace {
		logrus.SetLevel(logrus.TraceLevel)
	} else if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else if verbose {
		logrus.SetLevel(logrus.InfoLevel)
	} else {
		logrus.SetLevel(logrus.WarnLevel)
	}
	golog.SetOutput(ioutil.Discard)

	if cfgFileUsed != "" {
		logrus.Infof("Using config file: %s", cfgFileUsed)
	}

	Root.SilenceUsage = true
	Root.SilenceErrors = true

	return nil
}

func initConfig() {
	viper.SetConfigType("toml")
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			logrus.Fatal(err)
		}

		viper.AddConfigPath("/etc/mokey/")
		viper.AddConfigPath(cwd)
		viper.SetConfigName("mokey.toml")
	}

	server.SetDefaults()
	viper.AutomaticEnv()
	viper.SetEnvPrefix("mokey")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			logrus.Fatalf("Failed parsing config file %s: %s", viper.ConfigFileUsed(), err)
		}
	} else {
		cfgFileUsed = viper.ConfigFileUsed()
	}

	if !viper.IsSet("secret") {
		secret, err := server.GenerateSecret(32)
		if err != nil {
			logrus.Fatal(err)
		}

		viper.Set("secret", secret)
	}
}
