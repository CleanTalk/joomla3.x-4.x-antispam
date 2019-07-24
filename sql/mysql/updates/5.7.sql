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