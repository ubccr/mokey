package main

import (
    "fmt"
    "github.com/codegangsta/cli"
    "github.com/spf13/viper"
)

func init() {
    viper.SetConfigName("mokey")
    viper.SetConfigType("yaml")
    viper.AddConfigPath("/etc/mokey/")
}

func main() {
    app := cli.NewApp()
    app.Name    = "mokey"
    app.Authors = []cli.Author{cli.Author{Name: "Andrew E. Bruno", Email: "aebruno2@buffalo.edu"}}
    app.Usage   = "mokey"
    app.Version = "0.0.1"
    app.Flags   = []cli.Flag{
        &cli.StringFlag{Name: "conf,c", Usage: "Path to conf file"},
    }
    app.Before  = func(c *cli.Context) error {
        conf := c.GlobalString("conf")
        if len(conf) > 0 {
            viper.SetConfigFile(conf)
        }

        err := viper.ReadInConfig()
        if err != nil {
            return fmt.Errorf("Failed reading config file - %s", err)
        }

        return nil
    }
    app.Commands = []cli.Command {
        {
            Name: "server",
            Usage: "Run http server",
            Action: func(c *cli.Context) {
                Server()
            },
        }}

    app.RunAndExitOnError()
}
