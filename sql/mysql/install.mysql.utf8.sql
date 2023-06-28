CREATE TABLE IF NOT EXISTS `#__cleantalk_sfw` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `network` int(11) unsigned NOT NULL,
  `mask` int(11) unsigned NOT NULL,
  `status` tinyint(1) NOT NULL DEFAULT 0,
  `source` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX (  `network` ,  `mask` )
);
CREATE TABLE IF NOT EXISTS `#__cleantalk_sfw_logs` (
  `id` VARCHAR(40) NOT NULL,
  `ip` VARCHAR(15) NOT NULL,
  `status` ENUM('PASS_SFW','DENY_SFW','PASS_SFW__BY_WHITELIST','PASS_SFW__BY_COOKIE','DENY_ANTICRAWLER','PASS_ANTICRAWLER','DENY_ANTICRAWLER_UA','PASS_ANTICRAWLER_UA','DENY_ANTIFLOOD','PASS_ANTIFLOOD') NULL DEFAULT NULL,
  `all_entries` INT NOT NULL,
  `blocked_entries` INT NOT NULL,
  `entries_timestamp` INT NOT NULL,
  `ua_id` INT(11) NULL DEFAULT NULL,
  `ua_name` VARCHAR(1024) NOT NULL,
  `source` TINYINT NULL DEFAULT NULL,
  `network` VARCHAR(20) NULL DEFAULT NULL,
  `first_url`VARCHAR(100) NULL DEFAULT NULL,
  `last_url` VARCHAR(100) NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
);
CREATE TABLE IF NOT EXISTS `#__cleantalk_sessions` (
  `id` varchar(64) NOT NULL,
  `name` varchar(40) NOT NULL,
  `value` text NULL DEFAULT NULL,
  `last_update` datetime NULL DEFAULT NULL,
  PRIMARY KEY (`name`(40), `id`(64))
);
CREATE TABLE IF NOT EXISTS `#__cleantalk_ua_bl` (
    `id` int(11) NOT NULL,
    `ua_template` varchar(255) DEFAULT NULL,
    `ua_status` tinyint(4) DEFAULT NULL,
    PRIMARY KEY (`id`)
);
UPDATE `#__extensions` SET params = '{"ct_check_register":1,"ct_check_contact_forms":1,"check_search":1,"ct_jcomments_check_comments":1,"roles_exclusions":"administrator,super users","ct_set_cookies":1}'
WHERE element = 'cleantalkantispam' AND folder = 'system';
CREATE TABLE IF NOT EXISTS `#__cleantalk_usermeta` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `user_id` int(11) NOT NULL,
    `meta_key` varchar(255) DEFAULT NULL,
    `meta_value` longtext DEFAULT NULL,
    PRIMARY KEY (`id`)
);