<?php

namespace Cleantalk\ApbctJoomla;

use Cleantalk\Common\Helper as CleantalkHelper;
use Cleantalk\Common\API as CleantalkAPI;

/*
 * CleanTalk SpamFireWall base class
 * Compatible only with Wordpress.
 * Version 2.0-wp
 * author Cleantalk team (welcome@cleantalk.org)
 * copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * see https://github.com/CleanTalk/php-antispam
*/

class SFW
{
	public $ip = 0;
	public $ip_str = '';
	public $ip_array = Array();
	public $ip_str_array = Array();
	public $blocked_ip = '';
	public $passed_ip = '';
	public $result = false;
	
	//Database variables
	private $table_prefix;
	private $db;
	private $query;
	private $db_result;
	private $db_result_data = array();
	
	public function __construct()
	{
		$this->table_prefix = "#__";
		$this->db = \JFactory::getDBO();
	}
	
	public function unversal_query($query, $straight_query = false)
	{
		if($straight_query){
			$this->db_result = $this->db->setQuery($query);
			$this->db->execute();
		}
		else
			$this->query = $query;
	}
	
	public function unversal_fetch()
	{
		$this->db_result_data = $this->db->loadAssoc();
	}
	
	public function unversal_fetch_all()
	{
		$this->db_result_data = $this->db->loadAssocList();
	}
	
	
	/*
	*	Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, X-Real-Ip, Cf_Connecting_Ip)
	*	reutrns array('remote_addr' => 'val', ['x_forwarded_for' => 'val', ['x_real_ip' => 'val', ['cloud_flare' => 'val']]])
	*/
	static public function ip_get($ips_input = array('real', 'remote_addr', 'x_forwarded_for', 'x_real_ip', 'cloud_flare'), $v4_only = true){
		
		$result = (array)CleantalkHelper::ip_get($ips_input, $v4_only);
		
		$result = !empty($result) ? $result : array();
		
		if(isset($_GET['sfw_test_ip'])){
			if(CleantalkHelper::ip_validate($_GET['sfw_test_ip']) !== false)
				$result['sfw_test'] = $_GET['sfw_test_ip'];
		}
		
		return $result;
		
	}
	
	/*
	*	Checks IP via Database
	*/
	public function check_ip(){

		foreach($this->ip_array as $current_ip){
		
			$query = "SELECT 
				COUNT(network) AS cnt
				FROM `".$this->table_prefix."cleantalk_sfw`
				WHERE network = ".sprintf("%u", ip2long($current_ip))." & mask";
			$this->unversal_query($query,true);
			$this->unversal_fetch();

			if($this->db_result_data['cnt']){
				$this->result = true;
				$this->blocked_ip = $current_ip;
			}else{
				$this->passed_ip = $current_ip;
			}
		}
	}
		
	/*
	*	Add entry to SFW log
	*/
	public function sfw_update_logs($ip, $result){
		
		if($ip === NULL || $result === NULL){
			return;
		}
		
		$blocked = ($result == 'blocked' ? ' + 1' : '');
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

		$this->unversal_query($query,true);
	}
	
	/*
	* Updates SFW local base
	* 
	* return mixed true || array('error' => true, 'error_string' => STRING)
	*/
	public function sfw_update($ct_key, $file_url = null){

		if(!$file_url){

			$result = CleantalkAPI::method__get_2s_blacklists_db($ct_key, 'multifiles');

			if(empty($result['error'])){
			
				if( !empty($result['file_url']) ){

					if(CleantalkHelper::http__request($result['file_url'], array(), 'get_code') === 200) {

						if(ini_get('allow_url_fopen')) {

							$pattenrs = array();
							$pattenrs = array('get', 'async');		

							$this->unversal_query("TRUNCATE TABLE `".$this->table_prefix."cleantalk_sfw`",true);

							if (preg_match('/multifiles/', $result['file_url'])) {
								
								$gf = gzopen($result['file_url'], 'rb');

								if ($gf) {

									$file_urls = array();

									while(!gzeof($gf))
										$file_urls[] = trim(gzgets($gf, 1024));			

									gzclose($gf);

									return CleantalkHelper::http__request(
										\JUri::root(), 
										array(
											'spbc_remote_call_token'  => md5($ct_key),
											'spbc_remote_call_action' => 'sfw_update',
											'plugin_name'             => 'apbct',
											'file_urls'               => implode(',', $file_urls),
										),
										$pattenrs
									);								
								}
							}else {
								return CleantalkHelper::http__request(
									\JUri::root(), 
									array(
										'spbc_remote_call_token'  => md5($ct_key),
										'spbc_remote_call_action' => 'sfw_update',
										'plugin_name'             => 'apbct',
										'file_urls'               => $result['file_url'],
									),
									$pattenrs
								);								
							}
						}else
							return array('error' => 'ERROR_ALLOW_URL_FOPEN_DISABLED');
					}				
				}else
					return array('error' => 'BAD_RESPONSE');
			}else
				return $result;
		}else{
						
			if(CleantalkHelper::http__request($file_url, array(), 'get_code') === 200){ // Check if it's there
		
					$gf = gzopen($file_url, 'rb');

					if($gf){
						
						if(!gzeof($gf)){
							
							for($count_result = 0; !gzeof($gf); ){
	
								$query = "INSERT INTO `".$this->table_prefix."cleantalk_sfw` VALUES %s";
	
								for($i=0, $values = array(); 5000 !== $i && !gzeof($gf); $i++, $count_result++){
	
									$entry = trim(gzgets($gf, 1024));
	
									if(empty($entry)) continue;

									$entry = explode(',', $entry);
	
									// Cast result to int
									$ip   = preg_replace('/[^\d]*/', '', $entry[0]);
									$mask = preg_replace('/[^\d]*/', '', $entry[1]);
	
									if(!$ip || !$mask) continue;
	
									$values[] = '('. $ip .','. $mask .')';
	
								}

								if(!empty($values)){
									$query = sprintf($query, implode(',', $values).';');
									$this->unversal_query($query,true);
								}
								
							}
							
							gzclose($gf);
							return $count_result;
							
						}else
							return array('error' => 'ERROR_GZ_EMPTY');
					}else
						return array('error' => 'ERROR_OPEN_GZ_FILE');
			}else
				return array('error' => 'NO_REMOTE_FILE_FOUND');
		}
	}
	
	/*
	* Sends and wipe SFW log
	* 
	* returns mixed true || array('error' => true, 'error_string' => STRING)
	*/
	public function send_logs($ct_key){
		
		//Getting logs
		$query = "SELECT * FROM `".$this->table_prefix."cleantalk_sfw_logs`";
		$this->unversal_query($query,true);
		$this->unversal_fetch_all();
		
		if(count($this->db_result_data)){
			
			//Compile logs
			$data = array();
			foreach($this->db_result_data as $key => $value){
				$data[] = array(trim($value['ip']), $value['all_entries'], $value['all_entries']-$value['blocked_entries'], $value['entries_timestamp']);
			}
			unset($key, $value);
			
			//Sending the request
			$result = CleantalkAPI::method__sfw_logs($ct_key, $data);
			
			//Checking answer and deleting all lines from the table
			if(empty($result['error'])){
				if($result['rows'] == count($data)){
					$this->unversal_query("TRUNCATE TABLE `".$this->table_prefix."cleantalk_sfw_logs`",true);
					return true;
				}
			}else{
				return $result;
			}
				
		}else{
			return array('error' => true, 'error_string' => 'NO_LOGS_TO_SEND');
		}
	}
	
	/*
	* Shows DIE page
	* 
	* Stops script executing
	*/	
	public function sfw_die($api_key, $cookie_prefix = '', $cookie_domain = ''){

		// File exists?
		if(file_exists(dirname(__FILE__).'/../../sfw_die_page.html')){
			$sfw_die_page = file_get_contents(dirname(__FILE__).'/../../sfw_die_page.html');
		}else{
			die("IP BLACKLISTED");
		}
		
		// Service info
		$sfw_die_page = str_replace('{REMOTE_ADDRESS}', $this->blocked_ip, $sfw_die_page);
		$sfw_die_page = str_replace('{REQUEST_URI}', $_SERVER['REQUEST_URI'], $sfw_die_page);
		$sfw_die_page = str_replace('{SFW_COOKIE}', md5($this->blocked_ip.$api_key), $sfw_die_page);
		
		// Headers
		if(headers_sent() === false){
			header('Expires: '.date(DATE_RFC822, mktime(0, 0, 0, 1, 1, 1971)));
			header('Cache-Control: no-store, no-cache, must-revalidate');
			header('Cache-Control: post-check=0, pre-check=0', FALSE);
			header('Pragma: no-cache');
			header("HTTP/1.0 403 Forbidden");
			$sfw_die_page = str_replace('{GENERATED}', "", $sfw_die_page);
		}else{
			$sfw_die_page = str_replace('{GENERATED}', "<h2 class='second'>The page was generated at&nbsp;".date("D, d M Y H:i:s")."</h2>",$sfw_die_page);
		}
		
		die($sfw_die_page);
		
	}
}
