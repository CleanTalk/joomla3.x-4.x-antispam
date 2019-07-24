CREATE TABLE IF NOT EXISTS `#__cleantalk_sfw` (
  `network` int(10) unsigned NOT NULL,
  `mask` int(10) unsigned NOT NULL,
  KEY `network` (`network`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
CREATE TABLE IF NOT EXISTS `#__cleantalk_sfw_logs` (
  `ip` varchar(15) NOT NULL,
  `all_entries` int(11) NOT NULL,
  `blocked_entries` int(11) NOT NULL,  
  `entries_timestamp` int(11) NOT NULL,   
  PRIMARY KEY `ip` (`ip`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
UPDATE `#__extensions` SET params = '{"form_protection":["check_register","check_contact_forms","check_search"],"comments_and_messages":["jcomments_check_comments"]}' 
WHERE name = 'PLG_SYSTEM_CLEANTALK_NAME';