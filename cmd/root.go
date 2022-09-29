package cmd

import (
	"io/ioutil"
	golog "log"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubccr/mokey/model"
	"github.com/ubccr/mokey/util"
)

var (
	cfgFile     string
	cfgFileUsed string
	trace       bool
	debug       bool
	verbose     bool

	Root = &cobra.Command{
		Use:     "mokey",
		Version: util.Version,
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
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			logrus.Fatal(err)
		}

		viper.AddConfigPath("/etc/mokey/")
		viper.AddConfigPath(cwd)
		viper.SetConfigName("mokey")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("mokey")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err == nil {
		cfgFileUsed = viper.ConfigFileUsed()
	}

	if !viper.IsSet("secret") {
		secret, err := model.GenerateSecret(32)
		if err != nil {
			logrus.Fatal(err)
		}

		viper.Set("secret", secret)
	}
}
