# Dummy SQL file to set schema version to 1.1 so next update will work
CREATE TABLE IF NOT EXISTS `#__cleantalk_sessions` (
    `id` varchar(64) NOT NULL,
    `name` varchar(40) NOT NULL,
    `value` text NULL DEFAULT NULL,
    `last_update` datetime NULL DEFAULT NULL,
    PRIMARY KEY (`name`(40), `id`(64))
);