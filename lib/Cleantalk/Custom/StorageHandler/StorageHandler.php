<?php

namespace Cleantalk\Custom\StorageHandler;

class StorageHandler implements \Cleantalk\Common\StorageHandler\StorageHandler
{
	public function getSetting($setting_name)
	{
		$plg = self::getPlgEntry();

		$table = \JTable::getInstance('extension');
		$table->load((int) $plg->extension_id);
		$data = new \JRegistry($table->custom_data);
		$data_array = $data->toArray();
		if ( isset($data_array[$setting_name]) ) {
			return $data_array[$setting_name];
		}
		return null;
	}

	public function deleteSetting($setting_name)
	{
		$plg = self::getPlgEntry();

		$table = \JTable::getInstance('extension');
		$table->load((int) $plg->extension_id);
		$data = new \JRegistry($table->custom_data);
		$data_array = $data->toArray();
		if ( isset($data_array[$setting_name]) ) {
			$data->remove($setting_name);
		}
		$table->custom_data = $data->toString();
		$table->store();
	}

	public function saveSetting($setting_name, $setting_value)
	{
		$plg = self::getPlgEntry();

		$table = \JTable::getInstance('extension');
		$table->load((int) $plg->extension_id);
		$params = array($setting_name => $setting_value);
		$data = new \JRegistry($table->custom_data);
		foreach ($params as $k => $v) {
			$data->set($k, $v);
		}
		$table->custom_data = $data->toString();
		return $table->store();
	}

	public static function getUpdatingFolder()
	{
		return APBCT_DIR_PATH . DIRECTORY_SEPARATOR . 'cleantalk_fw_files' . DIRECTORY_SEPARATOR;
	}

	private static function getPlgEntry()
	{
		$db = \JFactory::getDBO();

		$query = $db->getQuery(true);
		$query
			->select($db->quoteName('extension_id'))
			->from($db->quoteName('#__extensions'))
			->where($db->quoteName('element') . ' = ' . $db->quote('cleantalkantispam'))
			->where($db->quoteName('folder') . ' = ' . $db->quote('system'));
		$db->setQuery($query);
		$db->execute();

		return $db->loadObject();
	}

	public static function getJsLocation()
	{
		return \JURI::root(true) . "/plugins/system/cleantalkantispam/js/ct-functions.js";
	}
}
