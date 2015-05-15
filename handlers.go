package main

import (
    "bytes"
    "errors"
    "strconv"
    "html/template"
    "net/http"
    "unicode/utf8"

    "golang.org/x/crypto/bcrypt"
    "github.com/gorilla/context"
    "github.com/justinas/nosurf"
    "github.com/ubccr/goipa"
    "github.com/ubccr/mokey/model"
    "github.com/Sirupsen/logrus"
    "github.com/spf13/viper"
)

func renderTemplate(w http.ResponseWriter, t *template.Template, data interface{}) {
    var buf bytes.Buffer
    err := t.ExecuteTemplate(&buf, "layout", data)

    if err != nil {
        logrus.Printf("Error rendering template: %s", err)
        http.Error(w, "Fatal error rendering template", http.StatusInternalServerError)
        return
    }

    buf.WriteTo(w)
}

func errorHandler(app *Application, w http.ResponseWriter, status int, message string) {
    w.WriteHeader(status)
    renderTemplate(w, app.templates["error.html"], message)
}

func setSecurityQuestion(app *Application, questions []*model.SecurityQuestion, qid, answer, uid string) (error) {
    if len(qid) == 0 || len(answer) == 0 {
        return errors.New("Please choose a security question and answer.")
    }

    if utf8.RuneCountInString(answer) < 2 || utf8.RuneCountInString(answer) > 100 {
        return errors.New("Invalid answer. Must be between 2 and 100 characters long.")
    }

    q, err := strconv.Atoi(qid)
    if err != nil {
        return errors.New("Invalid security question")
    }

    found := false
    for _, sq := range questions {
        if sq.Id == q {
            found = true
            break
        }
    }

    if found == false {
        return errors.New("Invalid security question")
    }

    hash, err := bcrypt.GenerateFromPassword([]byte(answer), bcrypt.DefaultCost)
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "uid": uid,
            "error": err.Error(),
        }).Error("failed to generate bcrypt hash of answer")
        return errors.New("Fatal system error. Please contact ccr-help.")
    }

    a := &model.SecurityAnswer{
        UserName: uid,
        QuestionId: q,
        Answer: string(hash),
    }

    err = model.StoreAnswer(app.db, a)
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "uid": uid,
            "error": err.Error(),
        }).Error("failed to save answer to the database")
        return errors.New("Fatal system error. Please contact ccr-help.")
    }

    return nil
}

func IndexHandler(app *Application) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := context.Get(r, "user").(*ipa.UserRecord)
        if user == nil {
            logrus.Error("index handler: user not found in request context")
            errorHandler(app, w, http.StatusInternalServerError, "")
            return
        }

        _, err := model.FetchAnswer(app.db, string(user.Uid))
        if err == nil {
            logrus.WithFields(logrus.Fields{
                "uid": user.Uid,
            }).Error("logged in user already activated. security answer exists in database")

            vars := map[string]interface{}{
                    "user": user,
                    "completed": true}

            renderTemplate(w, app.templates["index.html"], vars)
            return
        }

        questions, err := model.FetchQuestions(app.db)
        if err != nil {
            logrus.WithFields(logrus.Fields{
                "error": err.Error(),
            }).Error("Failed to fetch questions from database")
            errorHandler(app, w, http.StatusInternalServerError, "")
            return
        }

        message := ""
        completed := false

        if r.Method == "POST" {
            qid := r.FormValue("qid")
            answer := r.FormValue("answer")

            err := setSecurityQuestion(app, questions, qid, answer, string(user.Uid))
            if err != nil {
                message = err.Error()
                completed = false
            } else {
                completed = true
            }
        }

        vars := map[string]interface{}{
                "token": nosurf.Token(r),
                "user": user,
                "completed": completed,
                "questions": questions,
                "message": message}

        renderTemplate(w, app.templates["index.html"], vars)
    })
}

func setPasswordAndLogin(uid, pass string) (string, error) {
    c := &ipa.Client{
        Host: viper.GetString("ipahost"),
        KeyTab: viper.GetString("keytab")}

    rand, err := c.ResetPassword(uid)
    if err != nil {
        return "", err
    }

    err = c.ChangePassword(uid, rand, pass)
    if err != nil {
        return "", err
    }

    sess, err := c.Login(uid, pass)
    if err != nil {
        return "", err
    }

    return sess, nil
}

func tryAuth(app *Application, uid, pass string) (error) {
    if len(uid) == 0 || len(pass) == 0 {
        return errors.New("Please provide a uid/password")
    }

    _, err := model.FetchAnswer(app.db, uid)
    if err == nil {
        logrus.WithFields(logrus.Fields{
            "uid": uid,
        }).Error("tryauth: user already activated. security answer exists in database")
        return errors.New("This account has already been activated. If you feel this is an error, contact ccr-help.")
    }

    // Attempt authentication via existing CCR Kerb
    err = ccrAuth(uid, pass)
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "uid": uid,
            "error": err,
        }).Error("tryauth: failed login attempt")
        return errors.New("Invalid login")
    }

    return nil
}

func LoginHandler(app *Application) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        message := ""

        if r.Method == "POST" {
            uid := r.FormValue("uid")
            pass := r.FormValue("password")

            err := tryAuth(app, uid, pass)
            if err != nil {
                message = err.Error()
            } else {
                sid, err := setPasswordAndLogin(uid, pass)
                if err != nil {
                    logrus.WithFields(logrus.Fields{
                        "uid": uid,
                        "error": err.Error(),
                    }).Error("loginhandler: failed to set password")
                    errorHandler(app, w, http.StatusInternalServerError, "")
                    return
                }

                session, _ := app.cookieStore.Get(r, MOKEY_COOKIE_SESSION)
                session.Values[MOKEY_COOKIE_SID] = sid
                session.Values[MOKEY_COOKIE_USER] = uid
                err = session.Save(r, w)
                if err != nil {
                    logrus.WithFields(logrus.Fields{
                        "error": err.Error(),
                    }).Error("loginhandler: failed to save session")
                    errorHandler(app, w, http.StatusInternalServerError, "")
                    return
                }

                http.Redirect(w, r, "/", 302)
                return
            }
        }

        vars := map[string]interface{}{
                "token": nosurf.Token(r),
                "message": message}

        renderTemplate(w, app.templates["login.html"], vars)
    })
}
