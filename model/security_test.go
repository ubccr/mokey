// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"database/sql"
	"testing"
)

func TestSecurityQuestion(t *testing.T) {
	db, err := newTestDB()
	if err != nil {
		t.Fatal(err)
	}

	_, err = FetchAnswer(db, "usernotexist")
	if err != sql.ErrNoRows {
		t.Error(err)
	}

	uid := "mokeytestuser"
	ans := "secret answer"
	questions, err := FetchQuestions(db)
	if err != nil {
		t.Fatal(err)
	}

	if len(questions) == 0 {
		t.Fatal("No questions found")
	}

	quest := questions[0]

	err = StoreAnswer(db, uid, ans, quest.ID)
	if err != nil {
		t.Error(err)
	}

	sa, err := FetchAnswer(db, uid)
	if err != nil {
		t.Error(err)
	}

	if sa.QuestionID != quest.ID {
		t.Errorf("Incorrect question ID: got %d should be %d", sa.QuestionID, quest.ID)
	}

	if sa.Question != quest.Question {
		t.Errorf("Incorrect question: got %s should be %s", sa.Question, quest.Question)
	}

	if !sa.Verify(ans) {
		t.Errorf("Failed to verify answer")
	}

	err = RemoveAnswer(db, uid)
	if err != nil {
		t.Error(err)
	}

	_, err = FetchAnswer(db, uid)
	if err != sql.ErrNoRows {
		t.Error(err)
	}
}
