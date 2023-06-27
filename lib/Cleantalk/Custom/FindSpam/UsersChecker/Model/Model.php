<?php

namespace Cleantalk\Custom\FindSpam\UsersChecker\Model;

use JFactory;

class Model
{
	private $db;

	public function __construct()
	{
		$this->db = JFactory::getDBO();
	}

	/**
	 *
	 * @return int
	 */
	public function getUsersCount()
	{
		$this->db->setQuery("SELECT COUNT(*) FROM #__users");
		return (int) $this->db->loadRow()[0];
	}

	public function getUsersToCheck($limit)
	{
		$query = "SELECT id, email, registerDate FROM #__users AS users WHERE 
        	NOT EXISTS (SELECT id FROM #__cleantalk_usermeta AS usermeta WHERE usermeta.user_id = users.id) 
        	LIMIT " . (int) $limit;
		$this->db->setQuery($query);
		return $this->db->loadAssocList();
	}

	public function updateUserMeta($user_id, $meta_key, $meta_value)
	{
		$query = "INSERT INTO #__cleantalk_usermeta (user_id, meta_key, meta_value) VALUES ($user_id, '$meta_key', '$meta_value')";
		$this->db->setQuery($query);
		$this->db->execute();
	}

	public function clearUsersMeta($user_ids)
	{
		$query = "DELETE FROM #__cleantalk_usermeta WHERE user_id IN (" . $user_ids .")";
		$this->db->setQuery($query);
		$this->db->execute();
	}

	/**
	 *
	 * @return int
	 */
	public function getSpamUsersTotal()
	{
		$this->db->setQuery("SELECT COUNT(*) FROM #__users AS users 
    		INNER JOIN #__cleantalk_usermeta AS usermeta 
         	WHERE users.id = usermeta.user_id AND usermeta.meta_key = 'ct_marked_as_spam' AND usermeta.meta_value = '1'");
		return (int) $this->db->loadRow()[0];
	}

	public function getScanResults($limit, $offset)
	{
		$query = "SELECT * FROM #__users AS users 
    		INNER JOIN #__cleantalk_usermeta AS usermeta 
         	WHERE users.id = usermeta.user_id AND usermeta.meta_key = 'ct_marked_as_spam' AND usermeta.meta_value = '1' 
         	LIMIT " . (int) $limit . " OFFSET " . (int) $offset;
		$this->db->setQuery($query);
		return $this->db->loadAssocList();
	}

	public function clearScanResults()
	{
		$query = "TRUNCATE TABLE #__cleantalk_usermeta";
		$this->db->setQuery($query);
		$this->db->execute();
	}

	public function deleteUsers($user_ids)
	{
		$db = JFactory::getDBO();
		$db->setQuery("DELETE FROM `#__users` WHERE id IN (" . $user_ids . ")");
		$db->execute();
		$db->setQuery("DELETE FROM `#__user_usergroup_map` WHERE user_id IN (" . $user_ids . ")");
		$db->execute();
		$this->clearUsersMeta($user_ids);
		$db->setQuery("SHOW TABLES LIKE '#__jcomments'");
		$jtable = $db->loadAssocList();
		if (!empty($jtable))
		{
			$db->setQuery("DELETE FROM `#__jcomments` WHERE userid IN (" . $user_ids . ")");
			$db->execute();
		}
	}
}
