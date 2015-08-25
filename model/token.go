package model

import (
    "fmt" 
    "crypto/rand"
    "github.com/jmoiron/sqlx"
)

type Token struct {
    UserName             string      `db:"user_name"`
    Token                string      `db:"token"`
}

func randToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return fmt.Sprintf("%x", b)
}


func FetchToken(db *sqlx.DB, token string, maxAge int) (*Token, error) {
    t := Token{}
    err := db.Get(&t, "select user_name,token from token where token = ? and timestampdiff(SECOND, created_at, now()) <= ?", token, maxAge)
    if err != nil {
        return nil, err
    }

    return &t, nil
}

func SaveToken(db *sqlx.DB, uid string) (string, error) {
    t := Token{UserName: uid, Token: randToken()}
    _, err := db.NamedExec("replace into token (user_name,token,created_at) values (:user_name, :token, now())", t)
    if err != nil {
        return "", err
    }

    return t.Token, nil
}

func DestroyToken(db *sqlx.DB, token string) (error) {
    _, err := db.Exec("delete from token where token = ?", token)
    if err != nil {
        return err
    }

    return nil
}
