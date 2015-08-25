package model

import (
    "github.com/jmoiron/sqlx"
)

type SecurityAnswer struct {
    UserName             string      `db:"user_name"`
    QuestionId           int         `db:"question_id"`
    Answer               string      `db:"answer"`
}

type SecurityQuestion struct {
    Id                   int         `db:"id"`
    Question             string      `db:"question"`
}

func FetchAnswer(db *sqlx.DB, uid string) (*SecurityAnswer, error) {
    answer := SecurityAnswer{}
    err := db.Get(&answer, "select user_name,question_id,answer from security_answer where user_name = ?", uid)
    if err != nil {
        return nil, err
    }

    return &answer, nil
}

func StoreAnswer(db *sqlx.DB, answer *SecurityAnswer) (error) {
    _, err := db.NamedExec("replace into security_answer (user_name,question_id,answer,created_at) values (:user_name, :question_id, :answer, now())", answer)
    if err != nil {
        return err
    }

    return nil
}

func FetchQuestions(db *sqlx.DB) ([]*SecurityQuestion, error) {
    questions := []*SecurityQuestion{}
    err := db.Select(&questions, "select id,question from security_question")
    if err != nil {
        return nil, err
    }

    return questions, nil
}
