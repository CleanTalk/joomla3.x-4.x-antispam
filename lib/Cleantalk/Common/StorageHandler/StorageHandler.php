<?php

namespace Cleantalk\Common\StorageHandler;

interface StorageHandler
{
    public static function getSetting($setting_name);

    public static function deleteSetting($setting_name);

    public static function saveSetting($setting_name, $setting_value);

    public static function getUpdatingFolder();

    public static function getJsLocation();
}
