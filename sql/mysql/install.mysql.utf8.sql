CREATE TABLE IF NOT EXISTS `#__cleantalk_sfw` (
  `network` int(10) unsigned NOT NULL,
  `mask` int(10) unsigned NOT NULL,
  `status` tinyint(1) NOT NULL DEFAULT 0,
  KEY `network` (`network`)
);
CREATE TABLE IF NOT EXISTS `#__cleantalk_sfw_logs` (
  `ip` varchar(15) NOT NULL,
  `all_entries` int(11) NOT NULL,
  `blocked_entries` int(11) NOT NULL,  
  `entries_timestamp` int(11) NOT NULL,   
  PRIMARY KEY `ip` (`ip`)
);
CREATE TABLE IF NOT EXISTS `#__cleantalk_sessions` (
  `id` varchar(64) NOT NULL,
  `name` varchar(40) NOT NULL,
  `value` text NULL DEFAULT NULL,
  `last_update` datetime NULL DEFAULT NULL,
  PRIMARY KEY (`name`(40), `id`(64))
);
UPDATE `#__extensions` SET params = '{"form_protection":["check_register","check_contact_forms","check_search"],"comments_and_messages":["jcomments_check_comments"],"roles_exclusions":["7","8"],"cookies":["set_cookies"]}'
WHERE element = 'cleantalkantispam' AND folder = 'system';