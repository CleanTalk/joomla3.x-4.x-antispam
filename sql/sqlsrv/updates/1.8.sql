DROP TABLE IF EXISTS `#__cleantalk_sfw`;
DROP TABLE IF EXISTS `#__cleantalk_sfw_logs`;
DROP TABLE IF EXISTS `#__cleantalk_sessions`;
CREATE TABLE IF NOT EXISTS `#__cleantalk_sfw` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `network` int(11) unsigned NOT NULL,
  `mask` int(11) unsigned NOT NULL,
  `status` tinyint(1) NOT NULL DEFAULT 0,
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
  PRIMARY KEY (`id`)
);
CREATE TABLE IF NOT EXISTS `#__cleantalk_sessions` (
  `id` varchar(64) NOT NULL,
  `name` varchar(40) NOT NULL,
  `value` text NULL DEFAULT NULL,
  `last_update` datetime NULL DEFAULT NULL,
  PRIMARY KEY (`name`(40), `id`(64))
);