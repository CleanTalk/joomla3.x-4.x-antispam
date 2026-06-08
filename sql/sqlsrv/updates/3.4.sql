CREATE TABLE IF NOT EXISTS `#__cleantalk_sfw_personal` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `network` int(11) unsigned NOT NULL,
  `mask` int(11) unsigned NOT NULL,
  `status` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX (  `network` ,  `mask` )
);
