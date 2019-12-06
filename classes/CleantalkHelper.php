<?php
/**
 * Cleantalk's hepler class
 * 
 * Mostly contains request's wrappers.
 *
 * @version 2.4
 * @package Cleantalk
 * @subpackage Helper
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/php-antispam 
 *
 */

class CleantalkHelper
{
	const URL = 'https://api.cleantalk.org';

	public static $cdn_pool = array(
		'cloud_flare' => array(
			'ipv4' => array(
				'103.21.244.0/22',
				'103.22.200.0/22',
				'103.31.4.0/22',
				'104.16.0.0/12',
				'108.162.192.0/18',
				'131.0.72.0/22',
				'141.101.64.0/18',
				'162.158.0.0/15',
				'172.64.0.0/13',
				'173.245.48.0/20',
				'185.93.231.18/20', // User fix
				'185.220.101.46/20', // User fix
				'188.114.96.0/20',
				'190.93.240.0/20',
				'197.234.240.0/22',
				'198.41.128.0/17',
			),
			'ipv6' => array(
				'2400:cb00::/32',
				'2405:8100::/32',
				'2405:b500::/32',
				'2606:4700::/32',
				'2803:f800::/32',
				'2c0f:f248::/32',
				'2a06:98c0::/29',
			),
		),
	);
	
	public static $private_networks = array(
		'10.0.0.0/8',
		'100.64.0.0/10',
		'172.16.0.0/12',
		'192.168.0.0/16',
		'127.0.0.1/32',
	);
	
	/*
	*	Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, X-Real-Ip, Cf_Connecting_Ip)
	*	reutrns array('remote_addr' => 'val', ['x_forwarded_for' => 'val', ['x_real_ip' => 'val', ['cloud_flare' => 'val']]])
	*/
	static public function ip_get($ips_input = array('real', 'remote_addr', 'x_forwarded_for', 'x_real_ip', 'cloud_flare'), $v4_only = true)
	{
		$ips = array();
		foreach($ips_input as $ip_type){
			$ips[$ip_type] = '';
		} unset($ip_type);
				
		$headers = function_exists('apache_request_headers') ? apache_request_headers() : self::apache_request_headers();
		
		// REMOTE_ADDR
		if(isset($ips['remote_addr'])){
			$ips['remote_addr'] = $_SERVER['REMOTE_ADDR'];
		}
		
		// X-Forwarded-For
		if(isset($ips['x_forwarded_for'])){
			if(isset($headers['X-Forwarded-For'])){
				$tmp = explode(",", trim($headers['X-Forwarded-For']));
				$ips['x_forwarded_for']= trim($tmp[0]);
			}
		}
		
		// X-Real-Ip
		if(isset($ips['x_real_ip'])){
			if(isset($headers['X-Real-Ip'])){
				$tmp = explode(",", trim($headers['X-Real-Ip']));
				$ips['x_real_ip']= trim($tmp[0]);
			}
		}
		
		// Cloud Flare
		if(isset($ips['cloud_flare'])){
			if(isset($headers['Cf-Connecting-Ip'])){
				if(self::ip_mask_match($ips['remote_addr'], self::$cdn_pool['cloud_flare']['ipv4'])){
					$ips['cloud_flare'] = $headers['Cf-Connecting-Ip'];
				}
			}
		}
		
		// Getting real IP from REMOTE_ADDR or Cf_Connecting_Ip if set or from (X-Forwarded-For, X-Real-Ip) if REMOTE_ADDR is local.
		if(isset($ips['real'])){
			
			$ips['real'] = $_SERVER['REMOTE_ADDR'];
			
			// Cloud Flare
			if(isset($headers['Cf-Connecting-Ip'])){
				if(self::ip_mask_match($ips['real'], self::$cdn_pool['cloud_flare']['ipv4'])){
					$ips['real'] = $headers['Cf-Connecting-Ip'];
				}
			// Incapsula proxy
			}elseif(isset($headers['Incap-Client-Ip'])){
				$ips['real'] = $headers['Incap-Client-Ip'];
			// Private networks. Looking for X-Forwarded-For and X-Real-Ip
			}elseif(self::ip_mask_match($ips['real'], self::$private_networks)){
				if(isset($headers['X-Forwarded-For'])){
					$tmp = explode(",", trim($headers['X-Forwarded-For']));
					$ips['real']= trim($tmp[0]);
				}elseif(isset($headers['X-Real-Ip'])){
					$tmp = explode(",", trim($headers['X-Real-Ip']));
					$ips['real']= trim($tmp[0]);
				}
			}
		}
		
		// Validating IPs
		$result = array();
		foreach($ips as $key => $ip){
			if($v4_only){
				if(self::ip_validate($ip) == 'v4')
					$result[$key] = $ip;
			}else{
				if(self::ip_validate($ip))
					$result[$key] = $ip;
			}
		}
		
		$result = array_unique($result);
		
		return count($ips_input) > 1 
			? $result 
			: (reset($result) !== false
				? reset($result)
				: null);
	}

	/*
	*	Checking api_key
	*	returns (boolean)
	*/

	static public function apbct_key_is_correct($api_key = '') {

		return preg_match('/^[a-z\d]{3,15}$|^$/', $api_key);

	}
			
	/*
	 * Check if the IP belong to mask. Recursivly if array given
	 * @param ip string  
	 * @param cird mixed (string|array of strings)
	*/
	static public function ip_mask_match($ip, $cidr){
		if(is_array($cidr)){
			foreach($cidr as $curr_mask){
				if(self::ip_mask_match($ip, $curr_mask)){
					return true;
				}
			} unset($curr_mask);
			return false;
		}
		$exploded = explode ('/', $cidr);
		$net = $exploded[0];
		$mask = 4294967295 << (32 - $exploded[1]);
		return (ip2long($ip) & $mask) == (ip2long($net) & $mask);
	}
	
	/*
	*	Validating IPv4, IPv6
	*	param (string) $ip
	*	returns (string) 'v4' || (string) 'v6' || (bool) false
	*/
	static public function ip_validate($ip)
	{
		if(!$ip)                                                  return false; // NULL || FALSE || '' || so on...
		if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 'v4';  // IPv4
		if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'v6';  // IPv6
		                                                          return false; // Unknown
	}
	
	/*
	* Wrapper for sfw_logs API method
	* 
	* returns mixed STRING || array('error' => true, 'error_string' => STRING)
	*/
	static public function api_method__sfw_logs($api_key, $data, $do_check = true){
		
		$request = array(
			'auth_key' => $api_key,
			'method_name' => 'sfw_logs',
			'data' => json_encode($data),
			'rows' => count($data),
			'timestamp' => time()
		);
		$result = self::api_send_request($request);
		$result = $do_check ? self::api_check_response($result, 'sfw_logs') : $result;
		
		return $result;
	}
	
	/*
	* Wrapper for 2s_blacklists_db API method
	* 
	* returns mixed STRING || array('error' => true, 'error_string' => STRING)
	*/
	static public function api_method__get_2s_blacklists_db($api_key, $out = null, $do_check = true){
		
		$request = array(
			'method_name' => '2s_blacklists_db',
			'auth_key' => $api_key,
			'out' => $out,			
		);
		
		$result = self::api_send_request($request);
		$result = $do_check ? self::api_check_response($result, '2s_blacklists_db') : $result;
		
		return $result;
	}
	
	/**
	 * Function gets access key automatically
	 *
	 * @param string website admin email
	 * @param string website host
	 * @param string website platform
	 * @return type
	 */
	static public function api_method__get_api_key($email, $host, $platform, $agent = null, $timezone = null, $language = null, $ip = null, $do_check = true)
	{		
		$request = array(
			'method_name'          => 'get_api_key',
			'product_name'         => 'antispam',
			'email'                => $email,
			'website'              => $host,
			'platform'             => $platform,
			'agent'                => $agent,			
			'timezone'             => $timezone,
			'http_accept_language' => !empty($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : null,
			'user_ip'              => $ip ? $ip : self::ip_get(array('real'), false),
		);
		
		$result = self::api_send_request($request);
		$result = $do_check ? self::api_check_response($result, 'get_api_key') : $result;
		
		return $result;
	}
		
	/**
	 * Function gets information about renew notice
	 *
	 * @param string api_key
	 * @param string $path_to_cms Path to website
	 * @return type
	 */
	static public function api_method__notice_paid_till($api_key, $path_to_cms, $do_check = true)
	{
		$request = array(
			'method_name' => 'notice_paid_till',
			'path_to_cms' => $path_to_cms,
			'auth_key' => $api_key
		);
		
		$result = self::api_send_request($request);
		$result = $do_check ? self::api_check_response($result, 'notice_paid_till') : $result;
		
		return $result;
	}

	/**
	 * Function gets spam report
	 *
	 * @param string website host
	 * @param integer report days
	 * @return type
	 */
	static public function api_method__get_antispam_report($host, $period = 1)
	{
		$request=Array(
			'method_name' => 'get_antispam_report',
			'hostname' => $host,
			'period' => $period,
		);
		
		$result = self::api_send_request($request);
		// $result = $do_check ? self::api_check_response($result, 'get_antispam_report') : $result;
		
		return $result;
	}

	/**
	 * Function gets information about account
	 *
	 * @param string api_key
	 * @param string perform check flag
	 * @return mixed (STRING || array('error' => true, 'error_string' => STRING))
	 */
	static public function api_method__get_account_status($api_key, $do_check = true)
	{
		$request = array(
			'method_name' => 'get_account_status',
			'auth_key' => $api_key
		);
		
		$result = self::api_send_request($request);
		$result = $do_check ? self::api_check_response($result, 'get_account_status') : $result;
		
		return $result;
	}

	/**
	 * Function gets spam statistics
	 *
	 * @param string website host
	 * @param integer report days
	 * @return type
	 */
	static public function api_method__get_antispam_report_breif($api_key, $do_check = true)
	{
		
		$request = array(
			'method_name' => 'get_antispam_report_breif',
			'auth_key' => $api_key,		
		);
		
		$result = self::api_send_request($request);
		$result = $do_check ? self::api_check_response($result, 'get_antispam_report_breif') : $result;
		
		$tmp = array();
		for( $i = 0; $i < 7; $i++ )
			$tmp[ date( 'Y-m-d', time() - 86400 * 7 + 86400 * $i ) ] = 0;
		
		$result['spam_stat']    = array_merge( $tmp, isset($result['spam_stat']) ? $result['spam_stat'] : array() );
		$result['top5_spam_ip'] = isset($result['top5_spam_ip']) ? $result['top5_spam_ip'] : array();
		
		return $result;		
	}
	
	/**
	 * Function gets spam report
	 *
	 * @param string website host
	 * @param integer report days
	 * @return type
	 */
	static public function api_method__spam_check_cms($api_key, $data, $date = null, $do_check = true)
	{
		$request=Array(
			'method_name' => 'spam_check_cms',
			'auth_key' => $api_key,
			'data' => is_array($data) ? implode(',',$data) : $data,			
		);
		
		if($date) $request['date'] = $date;
		
		$result = self::api_send_request($request, self::URL, false, 30);
		$result = $do_check ? self::api_check_response($result, 'spam_check_cms') : $result;
		
		return $result;
	}

	/**
	 * Function sends raw request to API server
	 *
	 * @param string url of API server
	 * @param array data to send
	 * @param boolean is data have to be JSON encoded or not
	 * @param integer connect timeout
	 * @return type
	 */
	static public function api_send_request($data, $url = self::URL, $isJSON = false, $timeout=3, $ssl = false)
	{	
		
		$result = null;
		$curl_error = false;
		
		$original_data = $data;
		
		if(!$isJSON){
			$data = http_build_query($data);
			$data = str_replace("&amp;", "&", $data);
		}else{
			$data = json_encode($data);
		}
		
		if (function_exists('curl_init') && function_exists('json_decode')){
		
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Expect:'));
			
			if ($ssl === true) {
				curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
				curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            }else{
				curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
				curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
			}
			
			$result = curl_exec($ch);
			
			if($result === false){
				if($ssl === false){
					return self::api_send_request($original_data, $url, $isJSON, $timeout, true);
				}
				$curl_error = curl_error($ch);
			}
			
			curl_close($ch);
			
		}else{
			$curl_error = 'CURL_NOT_INSTALLED';
		}
		
		if($curl_error){
			
			$opts = array(
				'http'=>array(
					'method'  => "POST",
					'timeout' => $timeout,
					'content' => $data,
				)
			);
			$context = stream_context_create($opts);
			$result = @file_get_contents($url, 0, $context);
		}
		
		if(!$result && $curl_error)
			return json_encode(array('error' => true, 'error_string' => $curl_error));
		
		return $result;
	}

	/**
	 * Function checks server response
	 *
	 * @param string result
	 * @param string request_method
	 * @return mixed (array || array('error' => true))
	 */
	static public function api_check_response($result, $method_name = null)
	{	
		
		// Errors handling
		
		// Bad connection
		if(empty($result)){
			return array(
				'error' => true,
				'error_string' => 'CONNECTION_ERROR'
			);
		}
		
		// JSON decode errors
		$result = json_decode($result, true);
		if(empty($result)){
			return array(
				'error' => true,
				'error_string' => 'JSON_DECODE_ERROR'
			);
		}
		
		// cURL error
		if(!empty($result['error'])){
			return array(
				'error' => true,
				'error_string' => 'CONNECTION_ERROR: ' . $result['error_string'],
			);
		}
		
		// Server errors
		if($result && (isset($result['error_no']) || isset($result['error_message']))){
			return array(
				'error' => true,
				'error_string' => "SERVER_ERROR NO: {$result['error_no']} MSG: {$result['error_message']}",
				'error_no' => $result['error_no'],
				'error_message' => $result['error_message']
			);
		}
		
		// Pathces for different methods
		
		
		// Other methods
		if(isset($result['data']) && is_array($result['data'])){
			return $result['data'];
		}
	}
	
	static public function is_json($string)
	{
		return is_string($string) && is_array(json_decode($string, true)) ? true : false;
	}

	/*
	* Get data from submit recursively
	*/

	static public function get_fields_any($arr, $message = array(), $email = null, $nickname = array('nick' => '', 'first' => '', 'last' => ''), $subject = null, $contact = true, $prev_name = '')
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

		// Skip feilds with these strings and known service fields
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
			'formData_fields_\d+_id',
			'formData_fields_\d+_files.*',
			// E_signature
			'recipient_signature',
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

		// Field exclusions
		if( !is_null( CleantalkCustomConfig::get_fields_exclusions() ) ) {
			$fields_exclusions = CleantalkCustomConfig::get_fields_exclusions();
			foreach($fields_exclusions as &$fields_exclusion) {
				if( preg_match('/\[*\]/', $fields_exclusion ) ) {
					// I have to do this to support exclusions like 'submitted[name]'
					$fields_exclusion = str_replace( array( '[', ']' ), array( '_', '' ), $fields_exclusion );
				}
			}
			if ($fields_exclusions && is_array($fields_exclusions) && count($fields_exclusions) > 0)
				$skip_fields_with_strings = array_merge($skip_fields_with_strings, $fields_exclusions);
		}

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

					if (in_array($key, $skip_params, true) && $key != 0 && $key != '' || preg_match("/^ct_checkjs/", $key))
						$contact = false;

					if ($value === '')
						continue;

					// Skipping fields names with strings from (array)skip_fields_with_strings
					foreach ($skip_fields_with_strings as $needle)
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
					$value = urldecode( trim( $value ) ); // Fully cleaned message
					$value_for_email = trim( $value );    // Removes shortcodes to do better spam filtration on server side.

					// Email
					if ( ! $email && preg_match( "/^\S+@\S+\.\S+$/", $value_for_email ) ) {
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

					$temp = self::get_fields_any($value, $message, $email, $nickname, $subject, $contact, $prev_name);

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

	/**
	 * Valids email
	 * @return bool
	 * @since 1.5
	 */
	static public function validEmail($string)
	{
		if (!isset($string) || !is_string($string))
		{
			return false;
		}

		return preg_match("/^\S+@\S+$/i", $string);
	}
	/* 
	 * If Apache web server is missing then making
	 * Patch for apache_request_headers() 
	 */
	static function apache_request_headers(){
		
		$headers = array();	
		foreach($_SERVER as $key => $val){
			if(preg_match('/\AHTTP_/', $key)){
				$server_key = preg_replace('/\AHTTP_/', '', $key);
				$key_parts = explode('_', $server_key);
				if(count($key_parts) > 0 and strlen($server_key) > 2){
					foreach($key_parts as $part_index => $part){
						$key_parts[$part_index] = mb_strtolower($part);
						$key_parts[$part_index][0] = strtoupper($key_parts[$part_index][0]);					
					}
					$server_key = implode('-', $key_parts);
				}
				$headers[$server_key] = $val;
			}
		}
		return $headers;
	}	
}
