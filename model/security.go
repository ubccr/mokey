// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
    "github.com/jmoiron/sqlx"
)

type SecurityAnswer struct {
    UserName             string      `db:"user_name"`
    QuestionId           int         `db:"question_id"`
    Question             string      `db:"question"`
    Answer               string      `db:"answer"`
}

type SecurityQuestion struct {
    Id                   int         `db:"id"`
    Question             string      `db:"question"`
}

func FetchAnswer(db *sqlx.DB, uid string) (*SecurityAnswer, error) {
    answer := SecurityAnswer{}
    err := db.Get(&answer, "select a.user_name,a.question_id,q.question,a.answer from security_answer a join security_question q on a.question_id = q.id  where a.user_name = ?", uid)
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
