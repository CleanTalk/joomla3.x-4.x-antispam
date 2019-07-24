<?php

class CleantalkCustomConfig
{
	// Exclude urls from spam_check. List them separated by commas
	public static $cleantalk_url_exclusions = '';

	//Excludes fields from filtering. List them separated by commas
	public static $cleantalk_fields_exclusions = '';

	public static function get_url_exclusions()
	{
		return (!empty(self::$cleantalk_url_exclusions) ? explode(',', trim(self::$cleantalk_url_exclusions)) : null);
	}
	public static function get_fields_exclusions()
	{
		return (!empty(self::$cleantalk_fields_exclusions) ? explode(',', trim(self::$cleantalk_fields_exclusions)) : null);
	}
}