<?php

namespace Cleantalk\ApbctJoomla;

/*
 * CleanTalk SpamFireWall Joomla class
 * author Cleantalk team (welcome@cleantalk.org)
 * copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * see https://github.com/CleanTalk/php-antispam
*/

class SFW extends \Cleantalk\Antispam\SFW
{
	public function __construct($api_key) {
		parent::__construct($api_key, \JFactory::getDBO(), "#__");
	}

	protected function universal_query($query) {
		$this->db_query = $this->db->setQuery($query)->execute();
	}

	protected function universal_fetch() {
		return $this->db->loadAssoc();
	}
	
	protected function universal_fetch_all() {
		return $this->db->loadAssocList();
	}
}
