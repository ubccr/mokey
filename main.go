// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/mokey/server"
	"github.com/urfave/cli"
)

func init() {
	viper.SetConfigName("mokey")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/mokey/")
}

func main() {
	app := cli.NewApp()
	app.Name = "mokey"
	app.Authors = []cli.Author{cli.Author{Name: "Andrew E. Bruno", Email: "aebruno2@buffalo.edu"}}
	app.Usage = "mokey"
	app.Version = "0.0.6"
	app.Flags = []cli.Flag{
		&cli.StringFlag{Name: "conf,c", Usage: "Path to conf file"},
		&cli.BoolFlag{Name: "debug,d", Usage: "Print debug messages"},
	}
	app.Before = func(c *cli.Context) error {
		if c.GlobalBool("debug") {
			log.SetLevel(log.InfoLevel)
		} else {
			log.SetLevel(log.WarnLevel)
		}

		conf := c.GlobalString("conf")
		if len(conf) > 0 {
			viper.SetConfigFile(conf)
		}

		err := viper.ReadInConfig()
		if err != nil {
			return fmt.Errorf("Failed reading config file - %s", err)
		}

		if !viper.IsSet("enc_key") || !viper.IsSet("auth_key") {
			log.Fatal("Please ensure authentication and encryption keys are set")
		}

		return nil
	}
	app.Commands = []cli.Command{
		{
			Name:  "server",
			Usage: "Run http server",
			Action: func(c *cli.Context) error {
				err := server.Run()
				if err != nil {
					log.Fatal(err)
					return cli.NewExitError(err, 1)
				}

				return nil
			},
		}}

	app.RunAndExitOnError()
}
