package model

import (
    "fmt"
    "crypto/rand"
    "github.com/jmoiron/sqlx"
)

type Token struct {
    UserName             string      `db:"user_name"`
    Email                string      `db:"email"`
    Token                string      `db:"token"`
    Attempts             int         `db:"attempts"`
}

func randToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return fmt.Sprintf("%x", b)
}

func FetchTokenByUser(db *sqlx.DB, uid string, maxAge int) (*Token, error) {
    t := Token{}
    err := db.Get(&t, "select user_name,token,attempts,email from token where user_name = ? and timestampdiff(SECOND, created_at, now()) <= ?", uid, maxAge)
    if err != nil {
        return nil, err
    }

    return &t, nil
}

func FetchToken(db *sqlx.DB, token string, maxAge int) (*Token, error) {
    t := Token{}
    err := db.Get(&t, "select user_name,token,attempts,email from token where token = ? and timestampdiff(SECOND, created_at, now()) <= ?", token, maxAge)
    if err != nil {
        return nil, err
    }

    return &t, nil
}

func NewToken(db *sqlx.DB, uid, email string) (*Token, error) {
    t := Token{UserName: uid, Email: email, Token: randToken()}
    _, err := db.NamedExec("replace into token (user_name,email, token,attempts,created_at) values (:user_name, :email, :token, 0, now())", t)
    if err != nil {
        return nil, err
    }

    return &t, nil
}

func IncrementToken(db *sqlx.DB, token string) (error) {
    _, err := db.Exec("update token set attempts = attempts + 1 where token = ?", token)
    if err != nil {
        return err
    }

    return nil
}

func DestroyToken(db *sqlx.DB, token string) (error) {
    _, err := db.Exec("delete from token where token = ?", token)
    if err != nil {
        return err
    }

    return nil
}
