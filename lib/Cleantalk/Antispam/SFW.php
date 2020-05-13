<?php

namespace Cleantalk\Antispam;

use Cleantalk\Common\Helper as CleantalkHelper;
use Cleantalk\Common\API as CleantalkAPI;

/*
 * CleanTalk SpamFireWall base class
 * author Cleantalk team (welcome@cleantalk.org)
 * copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * see https://github.com/CleanTalk/php-antispam
*/

abstract class SFW
{
	private $api_key = '';
	private $table_prefix;
	private $ips_array = array();
	
	//Database variables
	protected $db;
	protected $db_query;
	
	function __construct($api_key, $db, $table_prefix) {
		$this->table_prefix = $table_prefix;
		$this->api_key = $api_key;
		$this->db = $db;
	}
	
	abstract protected function universal_query($query);
	
	abstract protected function universal_fetch();
	
	abstract protected function universal_fetch_all();	
	
	/*
	*	Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, X-Real-Ip, Cf_Connecting_Ip)
	*	reutrns array('remote_addr' => 'val', ['x_forwarded_for' => 'val', ['x_real_ip' => 'val', ['cloud_flare' => 'val']]])
	*/
	private function ip_get($v4_only = true) {

		$real_ip = (array)CleantalkHelper::ip_get(array('real'), $v4_only);
		$real_ip = !empty($real_ip) ? $real_ip[0] : ''; 

		$this->ips_array['real'] = array('ip' => $real_ip, 'in_list' => false);

		if(isset($_GET['sfw_test_ip'])) {
			if(CleantalkHelper::ip_validate($_GET['sfw_test_ip']) !== false) {
				$this->ips_array['test'] = array('ip' => $_GET['sfw_test_ip'], 'in_list' => false);
			}
		}
	}

	/*
	*	Checks IP via Database
	*/
	public function check_ip() {

		$this->ip_get();

		if (isset($_COOKIE['ct_sfw_pass_key']) && $_COOKIE['ct_sfw_pass_key'] == md5($this->ips_array['real']['ip'] . $this->api_key)) {
			if (isset($_COOKIE['ct_sfw_passed'])) {
				@setcookie('ct_sfw_passed'); //Deleting cookie
				$this->sfw_update_logs($this->ips_array['real']['ip'], false);				
			}
			return;
		}

		foreach ($this->ips_array as $type => $ip) {

			$current_ip_v4 = sprintf("%u", ip2long($ip['ip']));
			for ( $needles = array(), $m = 6; $m <= 32; $m ++ ) {
				$mask      = sprintf( "%u", ip2long( long2ip( - 1 << ( 32 - (int) $m ) ) ) );
				$needles[] = bindec( decbin( $mask ) & decbin( $current_ip_v4 ) );
			}
			$needles = array_unique( $needles );

			$query = "SELECT 
				network, mask, status
				FROM `".$this->table_prefix."cleantalk_sfw`
				WHERE network IN (". implode( ',', $needles ) .")
				AND network = " . $current_ip_v4 . " & mask
				ORDER BY status DESC LIMIT 1;";

			$this->universal_query($query);
			$result = $this->universal_fetch();

			if ($result) {
				if ($result['status'] == 0) {
					$this->ips_array[$type]['in_list'] = true;
					$this->sfw_update_logs($this->ips_array[$type]['ip'], true);			
				}
			}			
		}

		if (isset($this->ips_array['test']) || $this->ips_array['real']['in_list']) {
			$this->sfw_die();
		}

	}
		
	/*
	*	Add entry to SFW log
	*/
	protected function sfw_update_logs($ip, $desicion) {
		
		if($ip === NULL || $desicion === NULL) {
			return;
		}
		
		$blocked = $desicion ? ' + 1' : '';
		$time = time();
		
		$query = "INSERT INTO `".$this->table_prefix."cleantalk_sfw_logs`
		SET 
			ip = '$ip',
			all_entries = 1,
			blocked_entries = 1,
			entries_timestamp = '".intval($time)."'
		ON DUPLICATE KEY 
		UPDATE 
			all_entries = all_entries + 1,
			blocked_entries = blocked_entries".strval($blocked).",
			entries_timestamp = '".intval($time)."'";

		$this->universal_query($query);
	}
	
	/*
	* Updates SFW local base
	* 
	* return mixed true || array('error' => true, 'error_string' => STRING)
	*/
	public function sfw_update($file_url = null) {

		if(!$file_url) {

			$result = CleantalkAPI::method__get_2s_blacklists_db($this->api_key, 'multifiles');

			if(empty($result['error'])) {
			
				if( !empty($result['file_url']) ){

					if(CleantalkHelper::http__request($result['file_url'], array(), 'get_code') === 200) {

						if(ini_get('allow_url_fopen')) {

							$pattenrs = array();
							$pattenrs = array('get', 'async');		
							$base_host_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://".$_SERVER['HTTP_HOST'];

							$this->universal_query("TRUNCATE TABLE `".$this->table_prefix."cleantalk_sfw`");
							
							if (preg_match('/multifiles/', $result['file_url'])) {
								
								$gf = gzopen($result['file_url'], 'rb');

								if ($gf) {

									$file_urls = array();

									while(!gzeof($gf))
										$file_urls[] = trim(gzgets($gf, 1024));			

									gzclose($gf);

									return CleantalkHelper::http__request(
										$base_host_url, 
										array(
											'spbc_remote_call_token'  => md5($this->api_key),
											'spbc_remote_call_action' => 'sfw_update',
											'plugin_name'             => 'apbct',
											'file_urls'               => implode(',', $file_urls),
										),
										$pattenrs
									);								
								}
							}else {
								return CleantalkHelper::http__request(
									$base_host_url, 
									array(
										'spbc_remote_call_token'  => md5($this->api_key),
										'spbc_remote_call_action' => 'sfw_update',
										'plugin_name'             => 'apbct',
										'file_urls'               => $result['file_url'],
									),
									$pattenrs
								);								
							}
						} else
							return array('error' => 'ERROR_ALLOW_URL_FOPEN_DISABLED');
					}				
				} else
					return array('error' => 'BAD_RESPONSE');
			} else
				return $result;
		} else {
						
			if(CleantalkHelper::http__request($file_url, array(), 'get_code') === 200) { // Check if it's there
		
					$gf = gzopen($file_url, 'rb');

					if($gf){
						
						if(!gzeof($gf)) {
							
							for($count_result = 0; !gzeof($gf); ) {
	
								$query = "INSERT INTO `".$this->table_prefix."cleantalk_sfw` VALUES %s";
	
								for($i=0, $values = array(); 5000 !== $i && !gzeof($gf); $i++, $count_result++) {
	
									$entry = trim(gzgets($gf, 1024));
	
									if(empty($entry)) continue;

									$entry = explode(',', $entry);
	
									// Cast result to int
									$ip   = preg_replace('/[^\d]*/', '', $entry[0]);
									$mask = preg_replace('/[^\d]*/', '', $entry[1]);
									$private = isset($entry[2]) ? $entry[2] : 0;
	
									if(!$ip || !$mask) continue;
	
									$values[] = '('. $ip .','. $mask .', '. $private .')';
	
								}

								if(!empty($values)) {
									$query = sprintf($query, implode(',', $values).';');
									$this->universal_query($query);
								}
								
							}
							
							gzclose($gf);
							return $count_result;
							
						} else
							return array('error' => 'ERROR_GZ_EMPTY');
					} else
						return array('error' => 'ERROR_OPEN_GZ_FILE');
			} else
				return array('error' => 'NO_REMOTE_FILE_FOUND');
		}
	}
	
	/*
	* Sends and wipe SFW log
	* 
	* returns mixed true || array('error' => true, 'error_string' => STRING)
	*/
	public function send_logs() {
		
		//Getting logs
		$query = "SELECT * FROM `".$this->table_prefix."cleantalk_sfw_logs`";
		$this->universal_query($query);
		$result = $this->universal_fetch_all();
		
		if(count($result)) {
			
			//Compile logs
			$data = array();
			foreach($result as $key => $value) {
				$data[] = array(trim($value['ip']), $value['all_entries'], $value['all_entries']-$value['blocked_entries'], $value['entries_timestamp']);
			}
			unset($key, $value);
			
			//Sending the request
			$result = CleantalkAPI::method__sfw_logs($this->api_key, $data);
			
			//Checking answer and deleting all lines from the table
			if(empty($result['error'])) {
				if($result['rows'] == count($data)){
					$this->universal_query("TRUNCATE TABLE `".$this->table_prefix."cleantalk_sfw_logs`");
					return true;
				}
			} else {
				return $result;
			}
				
		} else {
			return array('error' => true, 'error_string' => 'NO_LOGS_TO_SEND');
		}
	}
	
	/*
	* Shows DIE page
	* 
	* Stops script executing
	*/	
	private function sfw_die($cookie_prefix = '', $cookie_domain = '') {

		// File exists?
		if(file_exists(dirname(__FILE__).'/../../sfw_die_page.html')) {
			$sfw_die_page = file_get_contents(dirname(__FILE__).'/../../sfw_die_page.html');
		} else {
			die("IP BLACKLISTED");
		}
		
		// Service info
		$sfw_die_page = str_replace('{REMOTE_ADDRESS}', $this->ips_array['real']['ip'], $sfw_die_page);
		$sfw_die_page = str_replace('{REQUEST_URI}', $_SERVER['REQUEST_URI'], $sfw_die_page);
		$sfw_die_page = str_replace('{SFW_COOKIE}', md5($this->ips_array['real']['ip'].$this->api_key), $sfw_die_page);
		if (isset($this->ips_array['test'])) {
			$sfw_die_page = str_replace('{TEST_IP}', 'Tested IP <b>' . $this->ips_array['test']['ip'] . '</b> - ' . ($this->ips_array['test']['in_list'] ? '<span style = "color:red">In list</span>': '<span style = "color:green">Not in list</span>'), $sfw_die_page);
		}
		
		// Headers
		if(headers_sent() === false) {
			header('Expires: '.date(DATE_RFC822, mktime(0, 0, 0, 1, 1, 1971)));
			header('Cache-Control: no-store, no-cache, must-revalidate');
			header('Cache-Control: post-check=0, pre-check=0', FALSE);
			header('Pragma: no-cache');
			header("HTTP/1.0 403 Forbidden");
			$sfw_die_page = str_replace('{GENERATED}', "", $sfw_die_page);
		} else {
			$sfw_die_page = str_replace('{GENERATED}', "<h2 class='second'>The page was generated at&nbsp;".date("D, d M Y H:i:s")."</h2>",$sfw_die_page);
		}
		
		die($sfw_die_page);
	}
}
