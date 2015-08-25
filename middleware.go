package main

import (
    "net/http"

    "github.com/Sirupsen/logrus"
    "github.com/gorilla/context"
    "github.com/justinas/nosurf"
    "github.com/ubccr/goipa"
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

// Nosurf is a wrapper for justinas' csrf protection middleware
func Nosurf() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return nosurf.New(next)
    }
}
