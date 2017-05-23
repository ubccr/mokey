DROP TABLE IF EXISTS `token`;
CREATE TABLE `token` (
    `user_name`      varchar(255)      NOT NULL,
    `email`          varchar(255)      NOT NULL,
    `token`          char(64)          NOT NULL,
    `attempts`       tinyint unsigned  NOT NULL,
    `created_at`     datetime          NOT NULL,
    PRIMARY KEY      (`user_name`),
    UNIQUE           (`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `security_answer`;
CREATE TABLE `security_answer` (
    `user_name`      varchar(255) NOT NULL,
    `question_id`    int(11)      NOT NULL,
    `answer`         varchar(255) NOT NULL,
    `created_at`     datetime     NOT NULL,
    PRIMARY KEY      (`user_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `security_question`;
CREATE TABLE `security_question` (
    `id`        int(11) NOT NULL AUTO_INCREMENT,
    `question`  varchar(255) NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY  `question` (`question`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO security_question SET question = "In what city or town does your nearest sibling live";
INSERT INTO security_question SET question = "In what year was your father born";
INSERT INTO security_question SET question = "In what year was your mother born";
INSERT INTO security_question SET question = "What is the country of your ultimate dream vacation";
INSERT INTO security_question SET question = "What is the name of the first beach you visited";
INSERT INTO security_question SET question = "What is the name of your favorite childhood teacher";
INSERT INTO security_question SET question = "What is the name of your favorite sports team";
INSERT INTO security_question SET question = "What is the title of your favorite book";
INSERT INTO security_question SET question = "What was the make and model of your first car";
INSERT INTO security_question SET question = "What was the name of your elementary / primary school";
INSERT INTO security_question SET question = "What was your maternal grandfather's first name";
INSERT INTO security_question SET question = "What were the last four digits of your childhood telephone number";
