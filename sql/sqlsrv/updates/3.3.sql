CREATE TABLE IF NOT EXISTS `#__cleantalk_usermeta` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `user_id` int(11) NOT NULL,
    `meta_key` varchar(255) DEFAULT NULL,
    `meta_value` longtext DEFAULT NULL,
    PRIMARY KEY (`id`)
);