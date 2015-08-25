package main

import (
    "fmt"
    "github.com/codegangsta/cli"
    "github.com/spf13/viper"
    "github.com/ubccr/mokey/model"
    "github.com/Sirupsen/logrus"
)

func init() {
    viper.SetConfigName("mokey")
    viper.SetConfigType("yaml")
    viper.AddConfigPath("/srv/mokey/")
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
        },
        {
            Name: "newacct",
            Usage: "Send new account email",
            Flags: []cli.Flag{
                &cli.StringFlag{Name: "uid, u", Usage: "User id"},
            },
            Action: func(c *cli.Context) {
                uid := c.String("uid")
                if len(uid) == 0 {
                    logrus.Fatal("Please provide a user uid")
                }

                app, err := NewApplication()
                if err != nil {
                    logrus.Fatal(err.Error())
                }

                client := NewIpaClient(true)
                userRec, err := client.UserShow(uid)
                if err != nil {
                    logrus.WithFields(logrus.Fields{
                        "uid": uid,
                        "ipa_client_error": err,
                    }).Error("failed to fetch user")
                    return
                }

                db, err := NewDb()
                if err != nil {
                    logrus.WithFields(logrus.Fields{
                        "uid": uid,
                        "error": err.Error(),
                    }).Error("failed to connecting to the database")
                }

                token, err := model.SaveToken(db, uid)
                if err != nil {
                    logrus.WithFields(logrus.Fields{
                        "uid": uid,
                        "error": err.Error(),
                    }).Error("failed to save token to the database")
                }

                vars := map[string]interface{}{
                        "user": userRec,
                        "link": fmt.Sprintf("%s/auth/setup/%s", viper.GetString("email_link_base"), token)}

                err = app.SendEmail(userRec, "New Account Setup", "setup-account.txt", vars)
                if err != nil {
                    logrus.WithFields(logrus.Fields{
                        "uid": uid,
                        "error": err,
                    }).Error("failed send email to user")
                    return
                }
            },
        }}

    app.RunAndExitOnError()
}
