CREATE TABLE `otp_token` (
    `user_name`      varchar(255) NOT NULL,
    `uri`            varchar(255) NOT NULL,
    `confirmed`      tinyint      NOT NULL,
    `created_at`     datetime     NOT NULL,
    PRIMARY KEY      (`user_name`)
);
