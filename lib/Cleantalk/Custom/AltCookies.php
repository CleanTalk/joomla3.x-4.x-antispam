<?php

namespace Cleantalk\Custom;

use Cleantalk\Common\Mloader\Mloader;
use JFactory;

class AltCookies
{
	private const SESSION_LIFE_TIME = 86400 * 2; // Two days

	private const SESSION_TABLE__NAME = 'cleantalk_sessions';

	/**
	 * @var string[]
	 */
	private static $allowed_alt_cookies = [
		'ct_ps_timestamp' => 'int',
		'ct_fkp_timestamp' => 'int',
		'ct_pointer_data' => 'string',
		'ct_timezone' => 'int',
		'ct_visible_fields' => 'string',
		'ct_visible_fields_count' => 'int',
		'ct_event_token' => 'hash',
		'apbct_cookies_test' => 'json',
		'apbct_timestamp' => 'int',
		'apbct_prev_referer' => 'url',
	];

	public static function removeOld()
	{
		$db = JFactory::getDbo();
		$query = $db->getQuery(true);

		$query->delete($db->quoteName('#__' . self::SESSION_TABLE__NAME));
		$query->where($db->quoteName('last_update') . ' < NOW() - INTERVAL '. self::SESSION_LIFE_TIME .' SECOND');

		$db->setQuery($query);
		$db->execute();
	}

	public static function set($name, $value)
	{
		$validated = self::validate([$name => $value]);
		if ( count($validated) > 0 && isset($validated[$name]) ) {
			// Replace value by validated value
			$value = $validated[$name];

			$db = JFactory::getDbo();
			$query = $db->getQuery(true);

			$columns = array('id', 'name', 'value', 'last_update');
			$values = array($db->quote(self::getId()), $db->quote($name), $db->quote($value), $db->quote(date('Y-m-d H:i:s')));
			$query
				->insert($db->quoteName('#__' . self::SESSION_TABLE__NAME))
				->columns($db->quoteName($columns))
				->values(implode(',', $values));
			$db->setQuery($query . '  ON DUPLICATE KEY UPDATE ' . $db->quoteName('value') . ' = '.$db->quote($value).', ' . $db->quoteName('last_update') . ' = ' . $db->quote(date('Y-m-d H:i:s')));
			$db->execute();
		}
	}

	public static function get($name)
	{
		$db = JFactory::getDbo();
		$query = $db->getQuery(true);

		$query->select($db->quoteName(array('value')));
		$query->from($db->quoteName('#__' . self::SESSION_TABLE__NAME));
		$query->where($db->quoteName('id') . ' = '. $db->quote(self::getId()));
		$query->where($db->quoteName('name') . ' = '. $db->quote($name));
		$db->setQuery($query);
		$value = $db->loadResult();

		if ( ! is_null($value) ) {
			return $value;
		}

		return null;
	}

	public static function setFromRemote($data)
	{
		$db = JFactory::getDbo();
		$columns = array(
			'id',
			'name',
			'value',
			'last_update'
		);
		$values = array();
		$query = $db->getQuery(true);
		$query->insert($db->quoteName('#__' . self::SESSION_TABLE__NAME));
		$query->columns($db->quoteName($columns));

		$data = self::validate($data);

		foreach ($data as $cookie_name => $cookie_value) {
			$values[] = implode(',', array(
				$db->quote(self::getId()),
				$db->quote($cookie_name),
				$db->quote($cookie_value),
				$db->quote(date('Y-m-d H:i:s'))
			));
		}

		$query->values($values);

		$db->setQuery($query . '  ON DUPLICATE KEY UPDATE value=VALUES(value), last_update=VALUES(last_update);');
		$db->execute();

		return ('XHR OK');
	}

	/**
	 * Get hash session ID
	 *
	 * @return string
	 */
	private static function getId()
	{
		/** @var \Cleantalk\Common\Helper\Helper $helper_class */
		$helper_class = Mloader::get('Helper');

		$id = $helper_class::ipGet()
			. filter_input(INPUT_SERVER, 'HTTP_USER_AGENT')
			. filter_input(INPUT_SERVER, 'HTTP_ACCEPT_LANGUAGE');
		return hash('sha256', $id);
	}

	/**
	 * Incoming data validation against allowed alt cookies and theirs types
	 *
	 * @param array $cookies_array
	 *
	 * @return array
	 */
	private static function validate($cookies_array)
	{
		// Incoming data validation against allowed alt cookies
		foreach ($cookies_array as $name => $value) {
			if ( ! array_key_exists($name, self::$allowed_alt_cookies) ) {
				unset($cookies_array[$name]);
				continue;
			}

			// Validate value type
			switch (self::$allowed_alt_cookies[$name]) {
				case 'int':
					$cookies_array[$name] = (int)$value;
					break;
				case 'bool':
					$cookies_array[$name] = (bool)$value;
					break;
				case 'string':
					if (is_array($value) || is_object($value)) {
						unset($cookies_array[$name]);
						break;
					}
					$cookies_array[$name] = (string)$value;
					break;
				case 'json':
					if ( ! is_string($value) || json_decode($value) === null ) {
						unset($cookies_array[$name]);
					}
					break;
				case 'url':
					if ( ! filter_var($value, FILTER_VALIDATE_URL) ) {
						unset($cookies_array[$name]);
					}
					break;
				case 'hash':
					if ( ! preg_match('/^[a-f0-9]{32,128}$/', $value) ) {
						unset($cookies_array[$name]);
					}
					break;
				default:
					// If the type is not recognized, remove the cookie
					unset($cookies_array[$name]);
			}
		}
		return $cookies_array;
	}
}
