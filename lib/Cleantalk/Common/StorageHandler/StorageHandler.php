<?php

namespace Cleantalk\Common\StorageHandler;

abstract class StorageHandler
{
	abstract public static function getSetting($setting_name);

	abstract public static function deleteSetting($setting_name);

	abstract public static function saveSetting($setting_name, $setting_value);

	abstract public static function getUpdatingFolder();

	abstract public static function getJsLocation();
}
