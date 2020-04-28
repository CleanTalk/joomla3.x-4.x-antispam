<?php

namespace Cleantalk\Common;

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

class Helper
{
	/**
	 * Default user agent for HTTP requests
	 */
	const AGENT = 'Cleatalk-Helper/3.2';

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
	
	/**
	 * Merging arrays without reseting numeric keys
	 *
	 * @param array $arr1 One-dimentional array
	 * @param array $arr2 One-dimentional array
	 *
	 * @return array Merged array
	 */
	static public function array_merge__save_numeric_keys($arr1, $arr2)
	{
		foreach($arr2 as $key => $val){
			$arr1[$key] = $val;
		}
		return $arr1;
	}
	/**
	 * Function sends raw http request
	 *
	 * May use 4 presets(combining possible):
	 * get_code - getting only HTTP response code
	 * async    - async requests
	 * get      - GET-request
	 * ssl      - use SSL
	 *
	 * @param string       $url     URL
	 * @param array        $data    POST|GET indexed array with data to send
	 * @param string|array $presets String or Array with presets: get_code, async, get, ssl, dont_split_to_array
	 * @param array        $opts    Optional option for CURL connection
	 *
	 * @return array|bool (array || array('error' => true))
	 */	
	static public function http__request($url, $data = array(), $presets = null, $opts = array())
	{
		if(function_exists('curl_init')){
			
			$ch = curl_init();
			
			if(!empty($data)){
				// If $data scalar converting it to array
				$data = is_string($data) || is_int($data) ? array($data => 1) : $data;
				// Build query
				$opts[CURLOPT_POSTFIELDS] = $data;
			}
			
			// Merging OBLIGATORY options with GIVEN options
			$opts = self::array_merge__save_numeric_keys(
				array(
					CURLOPT_URL => $url,
					CURLOPT_RETURNTRANSFER => true,
					CURLOPT_CONNECTTIMEOUT_MS => 3000,
					CURLOPT_FORBID_REUSE => true,
					CURLOPT_USERAGENT => self::AGENT . '; ' . ( isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : 'UNKNOWN_HOST' ),
					CURLOPT_POST => true,
					CURLOPT_SSL_VERIFYPEER => false,
					CURLOPT_SSL_VERIFYHOST => 0,
					CURLOPT_HTTPHEADER => array('Expect:'), // Fix for large data and old servers http://php.net/manual/ru/function.curl-setopt.php#82418
					CURLOPT_FOLLOWLOCATION => true,
					CURLOPT_MAXREDIRS => 5,
				),
				$opts
			);
			
			// Use presets
			$presets = is_array($presets) ? $presets : explode(' ', $presets);
			foreach($presets as $preset){
				
				switch($preset){
					
					// Do not follow redirects
					case 'dont_follow_redirects':
						$opts[CURLOPT_FOLLOWLOCATION] = false;
						$opts[CURLOPT_MAXREDIRS] = 0;
						break;
					
					// Get headers only
					case 'get_code':
						$opts[CURLOPT_HEADER] = true;
						$opts[CURLOPT_NOBODY] = true;
						break;
					
					// Make a request, don't wait for an answer
					case 'async':
						$opts[CURLOPT_CONNECTTIMEOUT_MS] = 1000;
						$opts[CURLOPT_TIMEOUT_MS] = 500;
						break;
					
					case 'get':
						$opts[CURLOPT_URL] .= $data ? '?' . str_replace("&amp;", "&", http_build_query($data)) : '';
						$opts[CURLOPT_CUSTOMREQUEST] = 'GET';
						$opts[CURLOPT_POST] = false;
						$opts[CURLOPT_POSTFIELDS] = null;
						break;
					
					case 'ssl':
						$opts[CURLOPT_SSL_VERIFYPEER] = true;
						$opts[CURLOPT_SSL_VERIFYHOST] = 2;
						if(defined('CLEANTALK_CASERT_PATH') && CLEANTALK_CASERT_PATH)
							$opts[CURLOPT_CAINFO] = CLEANTALK_CASERT_PATH;
						break;
					
					default:
						
						break;
				}
				
			}
			unset($preset);
			
			curl_setopt_array($ch, $opts);
			$result = curl_exec($ch);
			
			// RETURN if async request
			if(in_array('async', $presets))
				return true;
			
			if($result){
				
				if(strpos($result, PHP_EOL) !== false && !in_array('dont_split_to_array', $presets))
					$result = explode(PHP_EOL, $result);
				
				// Get code crossPHP method
				if(in_array('get_code', $presets)){
					$curl_info = curl_getinfo($ch);
					$result = $curl_info['http_code'];
				}
				curl_close($ch);
				$out = $result;
			}else
				$out = array('error' => curl_error($ch));
		}else
			$out = array('error' => 'CURL_NOT_INSTALLED');
		
		/**
		 * Getting HTTP-response code without cURL
		 */
		if($presets && ($presets == 'get_code' || (is_array($presets) && in_array('get_code', $presets)))
			&& isset($out['error']) && $out['error'] == 'CURL_NOT_INSTALLED'
		){
			$headers = get_headers($url);
			$out = (int)preg_replace('/.*(\d{3}).*/', '$1', $headers[0]);
		}
		
		return $out;
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
