<?php

namespace Cleantalk\Custom\Helper;

class Helper extends \Cleantalk\Common\Helper\Helper
{

    /**
     * Get fw stats from the storage.
     *
     * @return array
     * @example array( 'firewall_updating' => false, 'firewall_updating_id' => md5(), 'firewall_update_percent' => 0, 'firewall_updating_last_start' => 0 )
     * @important This method must be overloaded in the CMS-based Helper class.
     */
    public static function getFwStats()
    {
        //die( __METHOD__ . ' method must be overloaded in the CMS-based Helper class' );
        $plugin = \JPluginHelper::getPlugin('system', 'cleantalkantispam');
        $params = new \JRegistry($plugin->params);

        return array(
            'firewall_updating_id' => $params->get('firewall_updating_id'),
            'firewall_updating_last_start' => $params->get('firewall_updating_last_start', 0),
            'firewall_update_percent' => $params->get('firewall_update_percent', 0)
        );
    }

    /**
     * Save fw stats on the storage.
     *
     * @param array $fw_stats
     * @return bool
     * @important This method must be overloaded in the CMS-based Helper class.
     */
    public static function setFwStats( $fw_stats )
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

        if ($plg = $db->loadObject()) {
            $table = \JTable::getInstance('extension');
            $table->load((int) $plg->extension_id);
            $params = array();
            $params['firewall_updating_id'] = $fw_stats['firewall_updating_id'];
            $params['firewall_updating_last_start'] = $fw_stats['firewall_updating_last_start'];
            $params['firewall_update_percent'] = isset($fw_stats['firewall_update_percent']) ? $fw_stats['firewall_update_percent'] : 0;
            $jparams = new \JRegistry($table->params);
            foreach ($params as $k => $v)
                $jparams->set($k, $v);
            $table->params = $jparams->toString();
            $table->store();
        }
    }

    /**
     * Implement here any actions after SFW updating finished.
     *
     * @return void
     */
    public static function SfwUpdate_DoFinisnAction()
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

        if ($plg = $db->loadObject()) {
            $table = \JTable::getInstance('extension');
            $table->load((int) $plg->extension_id);
            $jparams = new \JRegistry($table->params);
            $jparams->set('sfw_last_check', time());
            $table->params = $jparams->toString();
            $table->store();
        }
    }

	/**
	 * Wrapper for http_request
	 * Requesting HTTP response code for $url
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
	public static function http__request__get_response_code($url ){
		return static::httpRequest( $url, array(), 'get_code');
	}

	/**
	 * Wrapper for http_request
	 * Requesting data via HTTP request with GET method
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
	public static function http__request__get_content($url ){
		return static::httpRequest( $url, array(), 'get dont_split_to_array');
	}

	/**
	 * Do the remote call to the host.
	 *
	 * @param string $rc_action
	 * @param array $request_params
	 * @param array $patterns
	 * @return array|bool
	 * @todo Have to replace this method to the new class like HttpHelper
	 */
	public static function http__request__rc_to_host($rc_action, $request_params, $patterns = array() )
	{
		$request_params__default = array(
			'spbc_remote_call_action' => $rc_action,
			'plugin_name'             => 'apbct',
		);

		$result__rc_check_website = static::httpRequest(
			static::getSiteUrl(),
			array_merge( $request_params__default, $request_params, array( 'test' => 'test' ) ),
			array( 'get', 'dont_split_to_array' )
		);

		if( empty( $result__rc_check_website['error'] ) ){

			if (is_string($result__rc_check_website) && preg_match('@^.*?OK$@', $result__rc_check_website)) {

				static::httpRequest(
					static::getSiteUrl(),
					array_merge( $request_params__default, $request_params ),
					array_merge( array( 'get', ), $patterns )
				);

			}else
				return array(
					'error' => 'WRONG_SITE_RESPONSE ACTION: ' . $rc_action . ' RESPONSE: ' . htmlspecialchars( substr(
							! is_string( $result__rc_check_website )
								? print_r( $result__rc_check_website, true )
								: $result__rc_check_website,
							0,
							400
						) )
				);
		}else
			return array( 'error' => 'WRONG_SITE_RESPONSE TEST ACTION: ' . $rc_action . ' ERROR: ' . $result__rc_check_website['error'] );

		return true;
	}

	/**
	 * Get site url for remote calls.
	 *
	 * @return string@important This method can be overloaded in the CMS-based Helper class.
	 *
	 */
	private static function getSiteUrl()
	{
		return ( isset( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://" . $_SERVER['HTTP_HOST'] . ( isset($_SERVER['SCRIPT_URL'] ) ? $_SERVER['SCRIPT_URL'] : '' );
	}

	/*
	* Get data from submit recursively
	*/
	static public function get_fields_any($arr, $fields_exclusions = '', $message = array(), $email = null, $nickname = array('nick' => '', 'first' => '', 'last' => ''), $subject = null, $contact = true, $prev_name = '')
	{

		//Skip request if fields exists
		$skip_params = array(
			'ipn_track_id',    // PayPal IPN #
			'txn_type',        // PayPal transaction type
			'payment_status',    // PayPal payment status
			'ccbill_ipn',        // CCBill IPN
			'ct_checkjs',        // skip ct_checkjs field
			'api_mode',         // DigiStore-API
			'loadLastCommentId', // Plugin: WP Discuz. ticket_id=5571
		);

		// Fields to replace with ****
		$obfuscate_params = array(
			'password',
			'pass',
			'pwd',
			'pswd'
		);

		// Skip fields with these strings and known service fields
		$skip_fields_with_strings = array(
			// Common
			'ct_checkjs', //Do not send ct_checkjs
			'nonce', //nonce for strings such as 'rsvp_nonce_name'
			'security',
			// 'action',
			'http_referer',
			'timestamp',
			'captcha',
			// Formidable Form
			'form_key',
			'submit_entry',
			// Custom Contact Forms
			'form_id',
			'ccf_form',
			'form_page',
			// Qu Forms
			'iphorm_uid',
			'form_url',
			'post_id',
			'iphorm_ajax',
			'iphorm_id',
			// Fast SecureContact Froms
			'fs_postonce_1',
			'fscf_submitted',
			'mailto_id',
			'si_contact_action',
			// Ninja Forms
			'formData_id',
			'formData_settings',
			// E_signature
			'recipient_signature',
			'avatar__file_image_data',
			'task',
			'page_url',
			'page_title',
			'Submit',
			'formId',
			'key',
			'id',
			'hiddenlists',
			'ctrl',
			'task',
			'option',
			'nextstep',
			'acy_source',
			'subid',
			'ct_action',
			'ct_method',
		);

		$skip_fields_with_strings_by_regexp = array(
			// Ninja Forms
			'formData_fields_\d+_id',
			'formData_fields_\d+_files.*',
			// E_signature
			'output_\d+_\w{0,2}',
			// Contact Form by Web-Settler protection
			'_formId',
			'_returnLink',
			// Social login and more
			'_save',
			'_facebook',
			'_social',
			'user_login-',
			// Contact Form 7
			'_wpcf7',
		);

		// Reset $message if we have a sign-up data
		$skip_message_post = array(
			'edd_action', // Easy Digital Downloads
		);

		foreach ($skip_params as $value)
		{
			if (@array_key_exists($value, $_GET) || @array_key_exists($value, $_POST))
				$contact = false;
		}
		unset($value);

		if (count($arr))
		{
			foreach ($arr as $key => $value)
			{

				if (gettype($value) == 'string')
				{
					$decoded_json_value = json_decode($value, true);
					if ($decoded_json_value !== null)
						$value = $decoded_json_value;
				}

				if (!is_array($value) && !is_object($value))
				{
					//Add custom exclusions
					if( is_string($fields_exclusions) && !empty($fields_exclusions) ) {
						$fields_exclusions = explode(",",$fields_exclusions);
						if (is_array($fields_exclusions) && !empty($fields_exclusions)) {
							foreach($fields_exclusions as &$fields_exclusion) {
								if( preg_match('/\[*\]/', $fields_exclusion ) ) {
									// I have to do this to support exclusions like 'submitted[name]'
									$fields_exclusion = str_replace( array( '[', ']' ), array( '_', '' ), $fields_exclusion );
								}
							}
							$skip_fields_with_strings = array_merge($skip_fields_with_strings, $fields_exclusions);
						}
					}
					if (in_array($key, $skip_params, true) && $key != 0 && $key != '' || preg_match("/^ct_checkjs/", $key))
						$contact = false;

					if ($value === '')
						continue;

					// Skipping fields names with strings from (array)skip_fields_with_strings
					foreach ($skip_fields_with_strings as $needle)
					{
						if ($prev_name . $key === $needle)
						{
							continue(2);
						}
					}
					unset($needle);

					// Skipping fields names with strings from (array)skip_fields_with_strings_by_regexp
					foreach ($skip_fields_with_strings_by_regexp as $needle)
					{
						if (preg_match("/" . $needle . "/", $prev_name . $key) == 1)
						{
							continue(2);
						}
					}
					unset($needle);

					// Obfuscating params
					foreach ($obfuscate_params as $needle)
					{
						if (strpos($key, $needle) !== false)
						{
							$value = self::obfuscate_param($value);
							continue(2);
						}
					}
					unset($needle);


					// Removes whitespaces
                    $value = !is_null($value) ? $value : '';
					$value = urldecode( trim( $value ) ); // Fully cleaned message
					$value_for_email = trim( $value );    // Removes shortcodes to do better spam filtration on server side.

					// Email
					if ( ! $email && preg_match( "/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/", $value_for_email ) ) {
						$email = $value_for_email;

						// Names
					} elseif (preg_match("/name/i", $key)) {

						preg_match("/((name.?)?(your|first|for)(.?name)?)$/", $key, $match_forename);
						preg_match("/((name.?)?(last|family|second|sur)(.?name)?)$/", $key, $match_surname);
						preg_match("/^(name.?)?(nick|user)(.?name)?$/", $key, $match_nickname);

						if (count($match_forename) > 1)
							$nickname['first'] = $value;
						elseif (count($match_surname) > 1)
							$nickname['last'] = $value;
						elseif (count($match_nickname) > 1)
							$nickname['nick'] = $value;
						else
							$nickname[$prev_name . $key] = $value;

						// Subject
					}
					elseif ($subject === null && preg_match("/subject/i", $key))
					{
						$subject = $value;

						// Message
					}
					else
					{
						$message[$prev_name . $key] = $value;
					}

				}
				elseif (!is_object($value))
				{

					$prev_name_original = $prev_name;
					$prev_name          = ($prev_name === '' ? $key . '_' : $prev_name . $key . '_');

					$temp = self::get_fields_any($value, $fields_exclusions, $message, $email, $nickname, $subject, $contact, $prev_name);

					$message  = $temp['message'];
					$email    = ($temp['email'] ? $temp['email'] : null);
					$nickname = ($temp['nickname'] ? $temp['nickname'] : null);
					$subject  = ($temp['subject'] ? $temp['subject'] : null);
					if ($contact === true)
						$contact = ($temp['contact'] === false ? false : true);
					$prev_name = $prev_name_original;
				}
			}
			unset($key, $value);
		}

		foreach ($skip_message_post as $v)
		{
			if (isset($_POST[$v]))
			{
				$message = null;
				break;
			}
		}
		unset($v);

		//If top iteration, returns compiled name field. Example: "Nickname Firtsname Lastname".
		if ($prev_name === '')
		{
			if (!empty($nickname))
			{
				$nickname_str = '';
				foreach ($nickname as $value)
				{
					$nickname_str .= ($value ? $value . " " : "");
				}
				unset($value);
			}
			$nickname = $nickname_str;
		}

		$return_param = array(
			'email'    => $email,
			'nickname' => $nickname,
			'subject'  => $subject,
			'contact'  => $contact,
			'message'  => $message
		);

		return $return_param;
	}

	/**
	 * Masks a value with asterisks (*) Needed by the getFieldsAny()
	 * @return string
	 */
	static public function obfuscate_param($value = null)
	{
		if ($value && (!is_object($value) || !is_array($value)))
		{
			$length = strlen($value);
			$value  = str_repeat('*', $length);
		}

		return $value;
	}

	/**
	 * Print html form for external forms()
	 * @return string
	 */
	static public function print_form($arr, $k)
	{
		foreach ($arr as $key => $value)
		{
			if (!is_array($value))
			{

				if ($k == '')
					print '<textarea name="' . $key . '" style="display:none;">' . htmlspecialchars($value) . '</textarea>';
				else
					print '<textarea name="' . $k . '[' . $key . ']" style="display:none;">' . htmlspecialchars($value) . '</textarea>';
			}
		}
	}
}
