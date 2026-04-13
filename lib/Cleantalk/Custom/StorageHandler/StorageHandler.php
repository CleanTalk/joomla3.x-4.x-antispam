<?php

namespace Cleantalk\Custom\StorageHandler;

use Cleantalk\Common\Mloader\Mloader;

class StorageHandler implements \Cleantalk\Common\StorageHandler\StorageHandler
{
    private $db_object;
    private $table_name;
    public function __construct()
    {
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $this->db_object = $db_class::getInstance();
        $this->table_name = $this->db_object->prefix . APBCT_TBL_STORAGE;
    }

    public function getSetting($setting_name)
    {
        $query = "SELECT value FROM {$this->table_name} WHERE name = %s;";
        $this->db_object->prepare($query, [$setting_name]);
        $result_raw = $this->db_object->fetch($this->db_object->getQuery());
        if ($result_raw && isset($result_raw['value'])) {
            $db_results = json_decode($result_raw['value'], true);
        } else {
            $db_results = null;
        }
        return $db_results;
    }

    public function deleteSetting($setting_name)
    {
        $query = "DELETE FROM {$this->table_name} WHERE name = %s;";
        $this->db_object->prepare($query, [$setting_name]);
        return $this->db_object->execute($this->db_object->getQuery());
    }

    public function saveSetting($setting_name, $setting_value)
    {
        is_int($setting_value) && $setting_value = (string)$setting_value;
        $setting_value_encoded = json_encode($setting_value);
        $query = "INSERT INTO {$this->table_name} (name, value) VALUES (%s, %s) 
              ON DUPLICATE KEY UPDATE value = %s;";
        $this->db_object->prepare($query, [$setting_name, $setting_value_encoded, $setting_value_encoded]);
        return $this->db_object->execute($this->db_object->getQuery());
    }

	public static function getUpdatingFolder()
	{
		return APBCT_DIR_PATH . DIRECTORY_SEPARATOR . 'cleantalk_fw_files' . DIRECTORY_SEPARATOR;
	}

	public static function getJsLocation()
	{
		return \JURI::root(true) . "/plugins/system/cleantalkantispam/js/ct-functions.js";
	}
}
