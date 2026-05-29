CREATE TABLE IF NOT EXISTS `#__cleantalk_usermeta` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `user_id` int(11) NOT NULL,
    `meta_key` varchar(255) DEFAULT NULL,
    `meta_value` longtext DEFAULT NULL,
    PRIMARY KEY (`id`)
);
CREATE TABLE IF NOT EXISTS `#__cleantalk_rate_limits` (
    uid VARCHAR(32) NOT NULL,
    type VARCHAR(32) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    ua VARCHAR(200) NOT NULL,
    counter INT NOT NULL DEFAULT 1,
    last_call INT NOT NULL,
    created_at INT NOT NULL,
    PRIMARY KEY (uid)
);
