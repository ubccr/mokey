DROP TABLE IF EXISTS `api_key`;
CREATE TABLE `api_key` (
    `user_name`      varchar(255)      NOT NULL,
    `client_id`      varchar(255)      NOT NULL,
    `api_key`        varchar(255)      NOT NULL,
    `scopes`         varchar(255)      NOT NULL,
    `created_at`     datetime          NOT NULL,
    `last_accessed`  datetime          NOT NULL,
    PRIMARY KEY      (`user_name`,`client_id`),
    UNIQUE           (`api_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
