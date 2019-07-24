<?php
defined('_JEXEC') or die('Restricted access');
if(!defined('DS')){ 
    define('DS', DIRECTORY_SEPARATOR);
}
require_once(dirname(__FILE__) . DS . 'classes'. DS .'Cleantalk.php');
require_once(dirname(__FILE__) . DS . 'classes'. DS .'CleantalkRequest.php');
require_once(dirname(__FILE__) . DS . 'classes'. DS .'CleantalkResponse.php');
require_once(dirname(__FILE__) . DS . 'classes'. DS .'CleantalkHelper.php');
require_once(dirname(__FILE__) . DS . 'classes'. DS .'CleantalkSFW.php');
?>