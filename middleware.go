// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package main

import (
    "net"
    "net/http"

    "github.com/Sirupsen/logrus"
    "github.com/gorilla/context"
    "github.com/justinas/nosurf"
    "github.com/ubccr/goipa"
    "github.com/garyburd/redigo/redis"
    "github.com/spf13/viper"
)


// AuthRequired checks existence of ipa session
func AuthRequired(app *Application, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session, _ := app.cookieStore.Get(r, MOKEY_COOKIE_SESSION)
        sid := session.Values[MOKEY_COOKIE_SID]
        userRec := session.Values[MOKEY_COOKIE_USER]

        if sid == nil || userRec == nil {
            http.Redirect(w, r, "/auth/login", 302)
            return
        }

        if _, ok := userRec.(*ipa.UserRecord); !ok {
            logrus.Error("Invalid user record in session.")
            http.Redirect(w, r, "/auth/login", 302)
            return
        }

        user := userRec.(*ipa.UserRecord)

        c := NewIpaClient(false)
        c.SetSession(sid.(string))

        _, err := c.Ping()
        if err != nil {
            logrus.WithFields(logrus.Fields{
                "uid": user.Uid,
                "error": err.Error(),
            }).Error("FreeIPA ping failed")
            http.Redirect(w, r, "/auth/login", 302)
            return
        }

        context.Set(r, "user", user)
        context.Set(r, "ipa", c)

        next.ServeHTTP(w, r)
    })
}

func RateLimit(app *Application, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
            next.ServeHTTP(w, r)
            return
        }

        remoteIP := r.Header.Get("X-Forwarded-For")
        if len(remoteIP) == 0 {
            remoteIP, _, _ = net.SplitHostPort(r.RemoteAddr)
        }
        path := r.URL.Path

        conn, err := redis.Dial("tcp", viper.GetString("redis"))
        if err != nil {
            logrus.WithFields(logrus.Fields{
                "path": path,
                "remoteIP": remoteIP,
                "err": err.Error(),
            }).Error("Failed connecting to redis server")
            next.ServeHTTP(w, r)
            return
        }
        defer conn.Close()


        current, err := redis.Int(conn.Do("INCR", path+remoteIP))
        if err != nil {
            logrus.WithFields(logrus.Fields{
                "path": path,
                "remoteIP": remoteIP,
                "err": err.Error(),
            }).Error("Failed to increment counter in redis")
            next.ServeHTTP(w, r)
            return
        }

        if current > viper.GetInt("rate_limit") {
            logrus.WithFields(logrus.Fields{
                "path": path,
                "remoteIP": remoteIP,
                "counter": current,
            }).Warn("Too many connections")
            w.WriteHeader(429)
            return
        }

        if current == 1 {
            _, err := conn.Do("SETEX", path+remoteIP, viper.GetInt("rate_expire"), 1)
            if err != nil {
                logrus.WithFields(logrus.Fields{
                    "path": path,
                    "remoteIP": remoteIP,
                    "err": err.Error(),
                }).Error("Failed to set expiry on counter in redis")
            }
        }

        logrus.WithFields(logrus.Fields{
            "path": path,
            "remoteIP": remoteIP,
            "counter": current,
        }).Info("rate limiting")

        next.ServeHTTP(w, r)
    })
}

// Nosurf is a wrapper for justinas' csrf protection middleware
func Nosurf() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return nosurf.New(next)
    }
}
