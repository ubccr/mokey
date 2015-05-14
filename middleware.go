package main

import (
    "net/http"

    "github.com/gorilla/context"
    "github.com/justinas/nosurf"
)


// AuthRequired checks existence of ipa session
func AuthRequired(app *Application, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session, _ := app.cookieStore.Get(r, MOKEY_COOKIE_SESSION)
        sid := session.Values[MOKEY_COOKIE_SID]
        user := session.Values[MOKEY_COOKIE_USER]

        if sid == nil || user == nil {
            http.Redirect(w, r, "/auth/login", 302)
            return
        }

        c := app.NewIpaClient(false)
        c.SetSession(sid.(string))
        userRec, err := c.UserShow(user.(string))
        if err != nil {
            http.Redirect(w, r, "/auth/login", 302)
            return
        }

        context.Set(r, "user", userRec)
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
