// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"github.com/jmoiron/sqlx"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type SecurityAnswer struct {
	UserName   string `db:"user_name"`
	QuestionID int    `db:"question_id"`
	Question   string `db:"question"`
	Answer     string `db:"answer"`
}

type SecurityQuestion struct {
	ID       int    `db:"id"`
	Question string `db:"question"`
}

// Verify security answer
func (a *SecurityAnswer) Verify(ans string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(a.Answer), []byte(ans))
	if err != nil {
		return false
	}

	return true
}

func FetchAnswer(db *sqlx.DB, uid string) (*SecurityAnswer, error) {
	answer := SecurityAnswer{}
	err := db.Get(&answer, "select a.user_name,a.question_id,q.question,a.answer from security_answer a join security_question q on a.question_id = q.id  where a.user_name = ?", uid)
	if err != nil {
		return nil, err
	}

	return &answer, nil
}

func StoreAnswer(db *sqlx.DB, user, ans string, qid int) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(ans), bcrypt.DefaultCost)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   user,
			"error": err.Error(),
		}).Error("failed to generate bcrypt hash of answer")
		return err
	}

	sa := &SecurityAnswer{
		UserName:   user,
		QuestionID: qid,
		Answer:     string(hash)}

	_, err = db.NamedExec("replace into security_answer (user_name,question_id,answer,created_at) values (:user_name, :question_id, :answer, now())", sa)
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

func RemoveAnswer(db *sqlx.DB, uid string) error {
	_, err := db.Exec("delete from security_answer where user_name = ?", uid)
	if err != nil {
		return err
	}

	return nil
}
