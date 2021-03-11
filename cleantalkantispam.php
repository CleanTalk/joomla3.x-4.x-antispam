<?php

/**
 * CleanTalk joomla plugin
 *
 * @version       1.8
 * @package       Cleantalk
 * @subpackage    Joomla
 * @author        CleanTalk (welcome@cleantalk.org)
 * @copyright (C) 2016 Сleantalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

defined('_JEXEC') or die('Restricted access');
jimport('joomla.plugin.plugin');
jimport('joomla.application.application');
jimport('joomla.application.component.helper');

// Sessions
define('APBCT_SESSION__LIVE_TIME', 86400*2);
define('APBCT_SESSION__CHANCE_TO_CLEAN', 100);

require_once(dirname(__FILE__) . '/lib/Cleantalk/Antispam/Cleantalk.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Antispam/CleantalkRequest.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Antispam/CleantalkResponse.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/API.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Helper.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/ApbctJoomla/Helper.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Cron.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/ApbctJoomla/Cron.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/DB.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/ApbctJoomla/DB.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/RemoteCalls.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/ApbctJoomla/RemoteCalls.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Schema.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Variables/ServerVariables.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Variables/Cookie.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Variables/Get.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Variables/Post.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Variables/Request.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Variables/Server.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Firewall/Firewall.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Firewall/FirewallModule.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Firewall/FirewallUpdater.php');
require_once(dirname(__FILE__) . '/lib/Cleantalk/Common/Firewall/Modules/SFW.php');


//Antispam classes
use Cleantalk\Antispam\Cleantalk as Cleantalk;
use Cleantalk\Antispam\CleantalkRequest as CleantalkRequest;
use Cleantalk\Antispam\CleantalkRequest as CleantalkResponse;

use Cleantalk\ApbctJoomla\DB;
use Cleantalk\Common\API as CleantalkAPI;
use Cleantalk\ApbctJoomla\Helper as CleantalkHelper;
use Cleantalk\ApbctJoomla\Cron;
use Cleantalk\Common\Schema;
use Cleantalk\Common\Firewall\Firewall;
use Cleantalk\Common\Firewall\Modules\SFW;
use Cleantalk\ApbctJoomla\RemoteCalls as RemoteCalls;
use Cleantalk\Common\Variables\Server;
use Cleantalk\Common\Variables\ServerVariables;

define('APBCT_TBL_FIREWALL_DATA', '#__cleantalk_sfw');      // Table with firewall data.
define('APBCT_TBL_FIREWALL_LOG',  '#__cleantalk_sfw_logs'); // Table with firewall logs.
define('APBCT_TBL_AC_LOG',        '#__cleantalk_ac_log');   // Table with firewall logs.
define('APBCT_TBL_AC_UA_BL',      '#__cleantalk_ua_bl');    // Table with User-Agents blacklist.
define('APBCT_TBL_SESSIONS',      '#__cleantalk_sessions'); // Table with session data.
define('APBCT_SPAMSCAN_LOGS',     '#__cleantalk_spamscan_logs'); // Table with session data.
define('APBCT_SELECT_LIMIT',      5000); // Select limit for logs.
define('APBCT_WRITE_LIMIT',       5000); // Write limit for firewall data.

class plgSystemCleantalkantispam extends JPlugin
{
	/**
	 * Plugin version string for server
     * @since         1.0
	 */
	const ENGINE = 'joomla34-18';

	/*
	 * Flag marked JComments form initilization.
	 * @since         1.0
	 */
	private $JCReady = false;

	/**
	 * Form submited without page load
     * @since         1.0
	 */
	private $ct_direct_post = 0;

	/**
	 * Plugin id
     * @since         1.0
	 */
	private $_id;

	/**
	 * Plugin params
     * @since         1.0
	 */
	public $params;

	/**
	 * Constructor
	 * @access public
     * @since         1.0
	 *
	 * @param $subject
	 * @param $config
	 *
	 * @return void
	 */
	public function __construct(&$subject, $config)
	{
		parent::__construct($subject, $config);

		// Get the plugin name.
		if (isset($config['name']))
		{
			$this->_name = $config['name'];
		}

		// Get the plugin type.
		if (isset($config['type']))
		{
			$this->_type = $config['type'];
		}
		// Get the plugin id.
		if (isset($config['id']))
		{
			$this->_id = $config['id'];
		}
		else $this->_id = $this->getId();

		// Get the parameters.
		if (isset($config['params']))
		{
			if ($config['params'] instanceof JRegistry)
			{
				$this->params = $config['params'];
			}
			else
			{
				$this->params = new JRegistry;
				$this->params->loadString($config['params']);
			}
		}
		$this->loadLanguage();
	}
	private function getId()
	{
		$db = JFactory::getDBO();

		$query = $db->getQuery(true);
		$query
			->select($db->quoteName('extension_id'))
			->from($db->quoteName('#__extensions'))
			->where($db->quoteName('element') . ' = ' . $db->quote('cleantalkantispam'))
			->where($db->quoteName('folder') . ' = ' . $db->quote('system'));
		$db->setQuery($query);
		$db->execute();

		if (!($plg = $db->loadObject()))
			return 0;
		else
			return (int) $plg->extension_id;
	}

	private function cleantalk_get_checkjs_code()
	{
		$keys = $this->params->get('js_keys') ? json_decode(json_encode($this->params->get('js_keys')), true) : null;

		$keys_checksum = md5(json_encode($keys));

		$key             = rand();
		$latest_key_time = 0;

		if ($keys && is_array($keys) && !empty($keys))
		{
			foreach ($keys as $k => $t)
			{

				// Removing key if it's to old
				if (time() - $t > 14 * 86400)
				{
					unset($keys[$k]);
					continue;
				}

				if ($t > $latest_key_time)
				{
					$latest_key_time = $t;
					$key             = $k;
				}
			}
			// Get new key if the latest key is too old
			if (time() - $latest_key_time > 86400)
			{
				$keys[$key] = time();
			}
		}
		else $keys = array($key => time());

		if (md5(json_encode($keys)) != $keys_checksum)
		{
			$save_params['js_keys'] = $keys;
			$this->saveCTConfig($save_params);
		}

		return $key;
	}

	/*
	* Checks if auth_key is paid or not
	*/

	private function checkIsPaid($ct_api_key = '', $force_check = false)
	{
		$api_key = trim($ct_api_key);

		if (($this->params->get('acc_status_last_check') && ($this->params->get('acc_status_last_check') < time() - 86400)) || $force_check || !$this->params->get('ct_key_is_ok'))
		{
			$ct_key_is_ok = 0;
			$key_is_valid = CleantalkHelper::key_is_correct($api_key);
			$save_params = array();
			$result = null;
			if ($key_is_valid){
				$result      = CleantalkAPI::method__notice_paid_till($api_key, preg_replace('/http[s]?:\/\//', '', $_SERVER['HTTP_HOST'], 1));
				$ct_key_is_ok = (empty($result['error']) && $result['valid']) ? 1 : 0;
			}
			
			$save_params['ct_key_is_ok']            = $ct_key_is_ok;
			$save_params['acc_status_last_check']   = time();
			$save_params['show_notice']             = (empty($result['error']) && isset($result['show_notice'])) ? $result['show_notice'] : 0;
			$save_params['renew']                   = (empty($result['error']) && isset($result['renew'])) ? $result['renew'] : 0;
			$save_params['trial']                   = (empty($result['error']) && isset($result['trial'])) ? $result['trial'] : 0;
			$save_params['user_token']              = (empty($result['error']) && isset($result['user_token'])) ? $result['user_token'] : '';
			$save_params['spam_count']              = (empty($result['error']) && isset($result['spam_count'])) ? $result['spam_count'] : 0;
			$save_params['moderate_ip']             = (empty($result['error']) && isset($result['moderate_ip'])) ? $result['moderate_ip'] : 0;
			$save_params['moderate']                = (empty($result['error']) && isset($result['moderate'])) ? $result['moderate'] : 0;
			$save_params['show_review']             = (empty($result['error']) && isset($result['show_review'])) ? $result['show_review'] : 0;
			$save_params['service_id']              = (empty($result['error']) && isset($result['service_id'])) ? $result['service_id'] : '';
			$save_params['license_trial']           = (empty($result['error']) && isset($result['license_trial'])) ? $result['license_trial'] : 0;
			$save_params['account_name_ob']         = (empty($result['error']) && isset($result['account_name_ob'])) ? $result['account_name_ob'] : '';
			$save_params['valid']                   = (empty($result['error']) && isset($result['valid'])) ? $result['valid'] : 0;
			$save_params['auto_update_app']         = (empty($result['error']) && isset($result['auto_update_app'])) ? $result['auto_update_app'] : 0;
			$save_params['show_auto_update_notice'] = (empty($result['error']) && isset($result['show_auto_update_notice'])) ? $result['show_auto_update_notice'] : 0;
			$save_params['ip_license']              = (empty($result['error']) && isset($result['ip_license'])) ? $result['ip_license'] : 0;

			$this->saveCTConfig($save_params);
		}

		return isset($save_params) ? $save_params : null;
	}

    /**
     * This event is triggered after Joomla initialization
     * @since Joomla 1.5
     * @access public
     * @throws Exception
     */

	public function onAfterInitialise()
	{
		$app = JFactory::getApplication();

		if (!$app->isAdmin())
		{
			// Remote calls
			if (isset($_GET['spbc_remote_call_token'], $_GET['spbc_remote_call_action'], $_GET['plugin_name']) && in_array($_GET['plugin_name'], array('antispam', 'anti-spam', 'apbct')))
			{
			    // Remote calls
			    if( RemoteCalls::check() ) {
			        $rc = new RemoteCalls( $this->params->get('apikey') );
			        $rc->perform();
			    }
			}
		}

		if ($app->isAdmin() && $app->input->get('layout') == 'edit' && $app->input->get('extension_id') == $this->_id)
		{
			$output      = null;
			$save_params = array();

			// Close review banner
			if (isset($_POST['ct_delete_notice']) && $_POST['ct_delete_notice'] === 'yes')
				$save_params['show_review_done'] = 1;

			// Getting key automatically
			if (isset($_POST['get_auto_key']) && $_POST['get_auto_key'] === 'yes')
			{
				$output = CleantalkAPI::method__get_api_key('antispam', JFactory::getConfig()->get('mailfrom'), $_SERVER['HTTP_HOST'], 'joomla3');
				// Checks if the user token is empty, then get user token by notice_paid_till()
				if( empty( $output['user_token'] ) && ! empty( $output['auth_key'] ) ){
					
					$result_tmp = CleantalkAPI::method__notice_paid_till($output['auth_key'], preg_replace('/http[s]?:\/\//', '', $_SERVER['HTTP_HOST'], 1));
					
					if( empty( $result_tmp['error'] ) )
						$output['user_token'] = $result_tmp['user_token'];
					
				}
			}


			// Check spam users
			if (isset($_POST['check_type']) && $_POST['check_type'] === 'users')
			{
				$improved_check = ($_POST['improved_check'] == 'true') ? true : false;
				$offset         = isset($_POST['offset']) ? $_POST['offset'] : 0;
				$on_page        = isset($_POST['amount']) ? $_POST['amount'] : 2;
				$output         = self::get_spam_users($offset, $on_page, $improved_check);
			}
			// Check spam comments
			if (isset($_POST['check_type']) && $_POST['check_type'] === 'comments')
			{
				$improved_check = ($_POST['improved_check'] == 'true') ? true : false;
				$offset         = isset($_POST['offset']) ? $_POST['offset'] : 0;
				$on_page        = isset($_POST['amount']) ? $_POST['amount'] : 2;
				$output         = self::get_spam_comments($offset, $on_page, $improved_check);
			}
			if (isset($_POST['ct_del_user_ids']))
			{
				$spam_users       = implode(',', $_POST['ct_del_user_ids']);
				$output['result'] = null;
				$output['data']   = null;
				try
				{
					$this->delete_users($spam_users);
					$output['result'] = 'success';
					$output['data']   = JText::sprintf('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_USERS_DELDONE', count($_POST['ct_del_user_ids']));
				}
				catch (Exception $e)
				{
					$output['result'] = 'error';
					$output['data']   = $e->getMessage();
				}
			}
			if (isset($_POST['ct_del_comment_ids']))
			{
				$spam_comments    = implode(',', $_POST['ct_del_comment_ids']);
				$output['result'] = null;
				$output['data']   = null;
				try
				{
					$this->delete_comments($spam_comments);
					$output['result'] = 'success';
					$output['data']   = JText::sprintf('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_COMMENTS_DELDONE', count($_POST['ct_del_comment_ids']));
				}
				catch (Exception $e)
				{
					$output['result'] = 'error';
					$output['data']   = $e->getMessage();
				}
			}
			if (isset($_POST['send_connection_report']) && $_POST['send_connection_report'] === 'yes')
			{
				$output['result']   = null;
				$output['data']     = null;
				$connection_reports = $this->params->get('connection_reports') ? json_decode(json_encode($this->params->get('connection_reports')), true) : null;
				if ($connection_reports && is_array($connection_reports) && count($connection_reports) > 0)
				{
					$to      = "welcome@cleantalk.org";
					$subject = "Connection report for " . $_SERVER['HTTP_HOST'];
					$message = ' 
					<html lang="en"> 
						<head> 
							<title></title> 
						</head> 
						<body> 
							<p>From ' . date('d M', $connection_reports['negative_report'][0]->date) . ' to ' . date('d M') . ' has been made ' . ($connection_reports['success'] + $connection_reports['negative']) . ' calls, where ' . $connection_reports['success'] . ' were success and ' . $connection_reports['negative'] . ' were negative</p> 
							<p>Negative report:</p>
							<table>  <tr>
						<td>&nbsp;</td>
						<td><b>Date</b></td>
						<td><b>Page URL</b></td>
						<td><b>Library report</b></td>
					  </tr>
					';
					foreach ($connection_reports['negative_report'] as $key => $report)
					{
						$message .= "<tr><td>" . ($key + 1) . ".</td><td>" . $report->date . "</td><td>" . $report->page_url . "</td><td>" . $report->lib_report . "</td></tr>";
					}
					$message .= '</table></body></html>';

					$headers = "Content-type: text/html; charset=windows-1251 \r\n";
					$headers .= "From: " . JFactory::getConfig()->get('mailfrom');
					mail($to, $subject, $message, $headers);
				}

				$output['result']                  = 'success';
				$output['data']                    = 'Success.';
				$save_params['connection_reports'] = array('success' => 0, 'negative' => 0, 'negative_report' => null);
			}

			if (isset($_POST['check_renew_banner'])) {
				$output['result'] = 'success';
				$output['close_renew_banner'] = $this->params->get('show_notice') == 0 ? 1 : 0;
			}

			if (isset($_POST['dev_insert_spam_users']) && $_POST['dev_insert_spam_users'] === 'yes')
			    // @ToDo This code block not used!
				$output = self::dev_insert_spam_users();

			$this->saveCTConfig($save_params);

			if ($output !== null)
			{
				print json_encode($output);
				$mainframe = JFactory::getApplication();
				$mainframe->close();
				die();
			}
		}
	}

	//Delete spam users
	private function delete_users($user_ids)
	{
		if (isset($user_ids))
		{
			$db = JFactory::getDBO();
			$db->setQuery("DELETE FROM `#__users` WHERE id IN (" . $user_ids . ")");
			$result = $db->execute();
			$db->setQuery("DELETE FROM `#__user_usergroup_map` WHERE user_id IN (" . $user_ids . ")");
			$result = $db->execute();
			$db->setQuery("SHOW TABLES LIKE '#__jcomments'");
			$jtable = $db->loadAssocList();
			if (!empty($jtable))
			{
				$db->setQuery("DELETE FROM `#__jcomments` WHERE userid IN (" . $user_ids . ")");
				$result = $db->execute();
			}
		}
	}

	//Delete spam comments
	private function delete_comments($comment_ids)
	{
		if (isset($comment_ids))
		{
			$db = JFactory::getDBO();
			$db->setQuery("DELETE FROM `#__jcomments` WHERE id IN (" . $comment_ids . ")");
			$result = $db->execute();
		}
	}

	/**
	 * Event triggered after update an extension
	 *
	 * @param   JInstaller  $installer    Installer instance
	 * @param   int         $extensionId  Extension Id
	 *
	 * @return void
	 */
	public function onExtensionAfterUpdate($installer, $extensionId)
	{
		//Sending agent version
		if ($this->params->get('apikey') && $this->params->get('apikey') !== '')
			$this->ctSendFeedback($this->params->get('apikey'), '0:' . self::ENGINE);
	}

    /**
     * This event is triggered after extension save their settings
     * Joomla 2.5+
     * @access public
     * @throws Exception
     */
	public function onExtensionAfterSave($name, $data)
	{
		$app = JFactory::getApplication();

		if ($app->input->get('layout') == 'edit' && $app->input->get('extension_id') == $this->_id)
		{
			if ($data->enabled)
			{
				$new_config = json_decode($data->params, true);
				$access_key = trim($new_config['apikey']);

				if (isset($new_config['other_settings']) && in_array('sfw_enable', $new_config['other_settings'])) {
					$this->apbct_sfw_update($access_key);
					$this->apbct_sfw_send_logs($access_key);
				}
				$this->ctSendFeedback($access_key, '0:' . self::ENGINE);

				$this->checkIsPaid($access_key, true);
			}
		}
	}

	/*
	exception for MijoShop ajax calls
	*/
	private function exceptionList()
	{
		$option_cmd = JFactory::getApplication()->input->get('option');
		$task_cmd   = JFactory::getApplication()->input->get('task');
		$module_cmd = JFactory::getApplication()->input->get('module');
		$method_cmd = JFactory::getApplication()->input->get('method');

		if ((@$_GET['option'] == 'com_mijoshop' && @$_GET['route'] == 'api/customer') ||
			($option_cmd == 'com_virtuemart' && $task_cmd == 'add') ||
			$option_cmd == 'com_jcomments' ||
			$option_cmd == 'com_contact' ||
			$option_cmd == 'com_users' ||
			$option_cmd == 'com_user' ||
			$option_cmd == 'com_login' ||
			$option_cmd == 'com_akeebasubs' ||
			$option_cmd == 'com_easysocial' ||
			($module_cmd == 'shoutbox' && $method_cmd == 'getPosts') ||
			($option_cmd == 'com_virtuemart' && $task_cmd == 'addJS') ||
			($option_cmd == 'com_virtuemart' && $task_cmd == 'cart') ||
			($option_cmd == 'com_rsform' && $task_cmd == 'ajaxValidate') // RSFrom ajax validation on multipage form
		)
			return true;

		return false;
	}

    /**
     * This event is triggered before an update of a user record.
     * @access public
     * @throws Exception
     */
	public function onUserBeforeSave($user, $isnew, $new)
	{
		if ($isnew)
			$this->moderateUser();

		return null;
	}

    /**
     * This event is triggered before an update of a user record.
     * Joomla 1.5
     * @access public
     * @throws Exception
     */
	public function onBeforeStoreUser($user, $isnew)
	{
		if ($isnew)
			$this->moderateUser();

		return null;
	}

	public function onAfterRender()
	{
		if ($this->params->get('other_settings') && in_array('tell_about_cleantalk', $this->params->get('other_settings')) && strpos($_SERVER['REQUEST_URI'], '/administrator/') === false)
		{
			if ($this->params->get('spam_count') && $this->params->get('spam_count') > 0)
				$code = "<div id='cleantalk_footer_link' style='width:100%;text-align:center;'><a href='https://cleantalk.org/joomla-anti-spam-plugin-without-captcha'>Anti-spam by CleanTalk</a> for Joomla!<br>" . $this->params->get('spam_count') . " spam blocked</div>";
			else
				$code = "<div id='cleantalk_footer_link' style='width:100%;text-align:center;'><a href='https://cleantalk.org/joomla-anti-spam-plugin-without-captcha'>Anti-spam by CleanTalk</a> for Joomla!<br></div>";

			//@ToDo Need to implement support for joomla 3.0 to 3.2 (replace getApplication() to JApplicationWeb::get_instance())
			$documentbody = JFactory::getApplication()->getBody();
			$documentbody = str_replace("</footer>", $code . " </footer>", $documentbody);
			JFactory::getApplication()->setBody($documentbody);
		}
	}

    /**
     * Save user registration request_id
     * @access public
     * @return void
     * @throws Exception
     */
	public function onBeforeCompileHead()
	{
		$config   = $this->params;
		$user     = JFactory::getUser();
		$app      = JFactory::getApplication();
		$document = JFactory::getDocument();

		JHtml::_('jquery.framework');

		if ($app->isSite())
		{
			$this->sfw_check();
			$this->ct_cookie();
			$document->addScript(JURI::root(true) . "/plugins/system/cleantalkantispam/js/ct-functions.js?" . time());
			$document->addScriptDeclaration('ctSetCookie("ct_checkjs", "' . $this->cleantalk_get_checkjs_code() . '", "0");');
			if ($config->get('form_protection') && in_array('check_external', $config->get('form_protection')))
				$document->addScript(JURI::root(true) . "/plugins/system/cleantalkantispam/js/ct-external.js?" . time());
		}

		if ($user->get('isRoot'))
		{
			if ($app->isAdmin())
			{
				if ($config->get('apikey'))
				{
					$this->checkIsPaid($config->get('apikey'));
				}

				$ct_key_is_ok       = ($config->get('ct_key_is_ok') && $config->get('ct_key_is_ok') == 1) ? 1 : 0;
				$show_notice        = ($config->get('show_notice') && $config->get('show_notice') == 1) ? 1 : 0;
				$trial              = ($config->get('trial') && $config->get('trial') == 1) ? 1 : 0;
				$renew 				= ($config->get('renew') && $config->get('renew') == 1) ? 1 : 0;
				$ct_ip_license      = $config->get('ip_license') ? $config->get('ip_license') : 0;
				$ct_moderate_ip     = $config->get('moderate_ip') ? $config->get('moderate_ip') : 0;
				$ct_user_token      = $config->get('user_token') ? $config->get('user_token') : '';
				$ct_service_id      = $config->get('service_id') ? $config->get('service_id') : 0;
				$ct_account_name_ob = $config->get('account_name_ob') ? $config->get('account_name_ob') : '';

				if (!$ct_key_is_ok)
					$notice = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_NOTICE_APIKEY');

				if ($show_notice == 1 && $trial == 1)
					$notice = JText::sprintf('PLG_SYSTEM_CLEANTALKANTISPAM_NOTICE_TRIAL', $config->get('user_token'));

				if ($show_notice == 1 && $renew == 1)
					$notice = JText::sprintf('PLG_SYSTEM_CLEANTALKANTISPAM_NOTICE_RENEW', $config->get('user_token'));

				$connection_reports = $config->get('connection_reports') ? json_decode(json_encode($config->get('connection_reports')), true) : array();
				$adminmail          = JFactory::getConfig()->get('mailfrom');

				// Passing parameters to JS
				$document->addScriptDeclaration('
					//Control params
					var ct_key_is_ok = "' . $ct_key_is_ok . '",
						cleantalk_domain="' . $_SERVER['HTTP_HOST'] . '",
						cleantalk_mail="' . $adminmail . '",
						ct_ip_license = "' . $ct_ip_license . '",
						ct_moderate_ip = "' . $ct_moderate_ip . '",
						ct_user_token="' . $ct_user_token . '",
						ct_service_id="' . $ct_service_id . '",
						ct_account_name_ob="' . $ct_account_name_ob . '",
						ct_connection_reports_success ="' . (isset($connection_reports['success']) ? $connection_reports['success'] : 0) . '",
						ct_connection_reports_negative ="' . (isset($connection_reports['negative']) ? $connection_reports['negative'] : 0) . '",
						ct_connection_reports_negative_report = "' . (isset($connection_reports['negative_report']) ? addslashes(json_encode($connection_reports['negative_report'])) : null) . '",
						ct_notice_review_done ='.(($config->get('show_review_done') && $config->get('show_review_done') === 1)?'true':'false').',
					
					//Translation
					    ct_autokey_label = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_AUTOKEY_LABEL') . '",
						ct_manualkey_label = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_MANUALKEY_LABEL') . '",
						ct_key_notice1 = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_NOTICE1') . '",
						ct_key_notice2 = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_NOTICE2') . '",
						ct_license_notice = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_LICENSE_NOTICE') . '",
						ct_statlink_label = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_STATLINK_LABEL') . '",
						ct_impspamcheck_label = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_IMPSPAMCHECK_LABEL') . '",
						ct_supportbtn_label = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SUPPORTBTN_LABEL') . '",
						ct_register_message="' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_REGISTER_MESSAGE') . $adminmail . '",
						ct_key_is_bad_notice = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_KEY_IS_BAD') . '",
						ct_register_error="' . addslashes(JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_ERROR_AUTO_GET_KEY')) . '",
						ct_spamcheck_checksusers = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_CHECKUSERS_LABEL') . '",
						ct_spamcheck_checkscomments = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_CHECKCOMMENTS_LABEL') . '",
						ct_spamcheck_notice = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_NOTICE') . '",
						ct_spamcheck_delsel = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_DELSEL') . '",
						ct_spamcheck_delall = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_DELALL') . '",
						ct_spamcheck_table_username = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_TABLE_USERNAME') . '",
						ct_spamcheck_table_joined = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_TABLE_JOINED') . '",
						ct_spamcheck_table_email = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_TABLE_EMAIL') . '",
						ct_spamcheck_table_lastvisit = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_TABLE_LASTVISIT') . '",
						ct_spamcheck_table_date = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_TABLE_DATE') . '",
						ct_spamcheck_table_text = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_TABLE_TEXT') . '",
						ct_spamcheck_users_delconfirm = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_USERS_DELCONFIRM') . '",
						ct_spamcheck_users_delconfirm_error = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_USERS_DELCONFIRM_ERROR') . '",
						ct_spamcheck_comments_delconfirm = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_COMMENTS_DELCONFIRM') . '",
						ct_spamcheck_comments_delconfirm_error = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_COMMENTS_DELCONFIRM_ERROR') . '",
						ct_spamcheck_load_more_results = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_LOAD_MORE_RESULTS') . '",
						ct_connection_reports_no_reports = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_CONNECTIONREPORTS_NO_REPORTS') . '",
						ct_connection_reports_send_report = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_CONNECTIONREPORTS_SENDBUTTON_LABEL') . '",
						ct_connection_reports_table_date = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_CONNECTIONREPORTS_TABLE_DATE') . '",
						ct_connection_reports_table_pageurl = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_CONNECTIONREPORTS_TABLE_PAGEURL') . '",
						ct_connection_reports_table_libreport = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_CONNECTIONREPORTS_TABLE_LIBREPORT') . '",
						ct_account_name_label = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_ACCOUNT_NAME_LABEL') . '",
						ct_form_settings_title = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_SETTINGS_TITLE') . '";																
				');
				//Admin JS and CSS
				$document->addScript(JURI::root(true) . "/plugins/system/cleantalkantispam/js/ct-settings.js?" . time());
				$document->addStyleSheet(JURI::root(true) . "/plugins/system/cleantalkantispam/css/ct-settings.css?" . time());

				if ($config->get('show_review') && $config->get('show_review') == 1 && $app->input->get('layout') == 'edit' && $app->input->get('extension_id') == $this->_id)
				{
					$document->addScriptDeclaration('var ct_show_feedback=true;');
					$document->addScriptDeclaration('var ct_show_feedback_mes="' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_FEEDBACKLINK') . '";');
				}
				else
					$document->addScriptDeclaration('var ct_show_feedback=false;');

			}
			if (isset($notice))
				JFactory::getApplication()->enqueueMessage($notice, 'notice');
		}

	}

    /**
     * onAfterRoute trigger - used by com_contact
     * @access public
     * @throws Exception
     * @since  1.5
     */
	public function onAfterRoute()
	{
		$app = JFactory::getApplication();

		$option_cmd = $app->input->get('option');
		$view_cmd   = $app->input->get('view');
		$task_cmd   = $app->input->get('task');
		$page_cmd   = $app->input->get('page');

		// constants can be found in  components/com_contact/views/contact/tmpl/default_form.php
		// 'option' and 'view' constants are the same in all versions
		//com_users - registration - registration.register
		if ($option_cmd == 'com_users')
		{
			if ($task_cmd == 'registration.register')
			{
			}
			else
			{
				$document = JFactory::getDocument();
				$document->addScriptDeclaration($this->fillRegisterFormScriptHTML('member-registration'));
			}
		}
		if ($option_cmd == 'com_virtuemart')
		{
			if ($task_cmd == 'editaddresscart')
			{
				$document = JFactory::getDocument();
				$document->addScriptDeclaration($this->fillRegisterFormScriptHTML('userForm'));
			}
			elseif ($task_cmd == 'registercartuser'
				|| $task_cmd == 'registercheckoutuser'
				|| $task_cmd == 'checkout' // OPC
			)
			{
				$this->moderateUser();
			}

		}
		if ($_SERVER['REQUEST_METHOD'] == 'GET')
		{
			if ($this->params->get('form_protection') && in_array('check_search', $this->params->get('form_protection')))
			{
				if (isset($_GET['searchword']) && $_GET['searchword'] != '' && (strpos($_SERVER['REQUEST_URI'], '/component/search/') !== false || strpos($_SERVER['REQUEST_URI'], '/components/search-component/') !== false)) // Search form
				{
					$post_info['comment_type'] = 'site_search_joomla34';
					$sender_email              = JFactory::getUser()->email;
					$sender_nickname           = JFactory::getUser()->username;
					$message                   = trim($_GET['searchword']);
					$ctResponse                = self::ctSendRequest(
						'check_message', array(
							'sender_nickname' => $sender_nickname,
							'sender_email'    => $sender_email,
							'message'         => trim(preg_replace("/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/", "\n", $message)),
							'post_info'       => json_encode($post_info),
						)
					);
					if ($ctResponse)
					{
						if (!empty($ctResponse) && is_array($ctResponse))
						{
							if ($ctResponse['errno'] != 0)
								$this->sendAdminEmail("CleanTalk. Can't verify search form!", $ctResponse['comment']);
							else
							{
								if ($ctResponse['allow'] == 0)
								{
									$error_tpl = file_get_contents(dirname(__FILE__) . "/lib/Cleantalk/Common/error.html");
									print str_replace('%ERROR_TEXT%', $ctResponse['comment'], $error_tpl);
									die();

								}
							}
						}
					}
				}
			}
		}

		if ($_SERVER['REQUEST_METHOD'] == 'POST')
		{
			$this->ct_direct_post = 1;

			/*
				Contact forms anti-spam code
			*/
			$sender_email    = null;
			$message         = '';
			$sender_nickname = null;
			$post_info       = array(
				'post_url' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
			);
			if ($app->input->get('option') == 'com_rsform')
				$post_info['comment_type'] = 'contact_form_joomla_rsform';
			if ($app->input->get('option') == 'com_baforms')
				$post_info['comment_type'] = 'contact_form_joomla_balbooa';
			if ($app->input->get('option') == 'com_acym' || $app->input->get('option') == 'com_acymailing')
				$post_info['comment_type'] = 'contact_form_joomla_acymailing';
			if ($app->input->get('option') == 'com_virtuemart' && $app->input->get('task') == 'savecheckoutuser')
				$post_info['comment_type'] = 'order';
			if (isset($_POST['cart_id']) && strpos($_SERVER['REQUEST_URI'], '/checkout') !== FALSE) {
				$post_info['comment_type'] = 'order';
			}
			//Rapid
			if (isset($_POST['rp_email']))
			{
				$sender_email = $_POST['rp_email'];

				if (isset($_POST["rp_subject"]))
					$message = $_POST["rp_subject"];

				if (isset($_POST['rp_message']))
					$message .= ' ' . $_POST['rp_message'];
				$post_info['comment_type'] = 'contact_form_joomla_rapid';
				
			} //VTEM Contact
			elseif (isset($_POST["vcontact_email"]))
			{
				$sender_email = $_POST['vcontact_email'];
				if (isset($_POST["vcontact_subject"]))
					$message = $_POST["vcontact_subject"];

				if (isset($_POST["vcontact_message"]))
					$message .= ' ' . $_POST["vcontact_message"];

				if (isset($_POST["vcontact_name"]))
					$sender_nickname = $_POST["vcontact_name"];
				$post_info['comment_type'] = 'contact_form_joomla_vtem';
				
			//BreezingForms
			}elseif (isset($_POST['ff_task']) && $_POST['ff_task'] == 'submit'){
				
				$ct_temp_msg_data = CleantalkHelper::get_fields_any($_POST, $this->params->get('fields_exclusions'));
				
				$sender_email     = ($ct_temp_msg_data['email'] ? $ct_temp_msg_data['email'] : '');
				$sender_nickname  = ($ct_temp_msg_data['nickname'] ? $ct_temp_msg_data['nickname'] : '');
				$subject          = ($ct_temp_msg_data['subject'] ? $ct_temp_msg_data['subject'] : '');
				$contact_form     = ($ct_temp_msg_data['contact'] ? $ct_temp_msg_data['contact'] : true);
				$message          = ($ct_temp_msg_data['message'] ? $ct_temp_msg_data['message'] : array());
				
				if ($subject != '')
					$message = array_merge(array('subject' => $subject), $message);
				$message = json_encode( $message );
				
				$post_info['comment_type'] = 'contact_form_joomla_breezing';
			}
			elseif ($app->input->get('option') == 'com_virtuemart' && $app->input->get('task') == 'review')
			{
				$sender_email    = JFactory::getUser()->email;
				$sender_nickname = JFactory::getUser()->username;
				$message         = isset($_POST['comment']) ? $_POST['comment'] : '';
			}
			// SP Builder Forms integration
			elseif ( $app->input->get('option') === 'com_sppagebuilder' )
			{
				$post_processed = array();
				if (isset($_POST['data'])) {
					foreach( $_POST['data'] as $item => $value ) {
						if( $value['name'] === 'from_name' || $value['name'] === 'from_email' ) {
							// These are the service fields
							continue;
						}
						$post_processed[$value['name']] = $value['value'];
					}
				} else {
					$post_processed = $_POST;
				}
				$ct_temp_msg_data = CleantalkHelper::get_fields_any($post_processed, $this->params->get('fields_exclusions'));
				$sender_email     = ($ct_temp_msg_data['email'] ? $ct_temp_msg_data['email'] : '');
				$sender_nickname  = ($ct_temp_msg_data['nickname'] ? $ct_temp_msg_data['nickname'] : '');
				$subject          = ($ct_temp_msg_data['subject'] ? $ct_temp_msg_data['subject'] : '');
				$contact_form     = ($ct_temp_msg_data['contact'] ? $ct_temp_msg_data['contact'] : true);
				$message          = ($ct_temp_msg_data['message'] ? $ct_temp_msg_data['message'] : array());

				if ($subject != '')
					$message = array_merge(array('subject' => $subject), $message);
				$message = json_encode( $message );
			}
			
			// Genertal test for any forms or form with custom fields
			elseif (
			    $this->params->get('form_protection') &&
			    ( $this->params->get('form_protection') && in_array('check_custom_contact_forms', $this->params->get('form_protection')) ) ||
			    ( $this->params->get('form_protection') && in_array('check_external', $this->params->get('form_protection')) )||
				$app->input->get('option') == 'com_rsform' ||
				$app->input->get('option') == 'com_virtuemart' ||
				$app->input->get('option') == 'com_baforms' ||
				$app->input->get('option') == 'com_acym' ||
				$app->input->get('option') == 'com_acymailing'
            )
			{
				$ct_temp_msg_data = CleantalkHelper::get_fields_any($_POST, $this->params->get('fields_exclusions'));
				$sender_email     = ($ct_temp_msg_data['email'] ? $ct_temp_msg_data['email'] : '');
				$sender_nickname  = ($ct_temp_msg_data['nickname'] ? $ct_temp_msg_data['nickname'] : '');
				$subject          = ($ct_temp_msg_data['subject'] ? $ct_temp_msg_data['subject'] : '');
				$contact_form     = ($ct_temp_msg_data['contact'] ? $ct_temp_msg_data['contact'] : true);
				$message          = ($ct_temp_msg_data['message'] ? $ct_temp_msg_data['message'] : array());

				if ($subject != '')
					$message = array_merge(array('subject' => $subject), $message);
				$message = json_encode( $message );

			}
			
			if (
				! empty( $_POST ) &&
				! $this->exceptionList() &&
				(
					! empty( $sender_email ) ||
					( $this->params->get( 'data_processing' ) && in_array( 'check_all_post', $this->params->get( 'data_processing' ) ) )
				) &&
				( $this->params->get( 'form_protection' ) &&
				  (
					  in_array( 'check_custom_contact_forms', $this->params->get( 'form_protection' ) ) ||
					  in_array( 'check_external',             $this->params->get( 'form_protection' ) ) ||
					  in_array( 'check_contact_forms',        $this->params->get( 'form_protection' ) )
				  )
				)
			){
			    if(
                    $task_cmd === 'registration.register' &&
			        $this->params->get('form_protection') &&
                    in_array('check_register', $this->params->get('form_protection'))
                )
			    {
			        // If this request is a registration - jump to the onValidateContact trigger
			        return;
                }
                if(
                    $option_cmd === 'com_jcomments' &&
                    $this->params->get('comments_and_messages') &&
                    in_array('jcomments_check_comments', $this->params->get('comments_and_messages'))
                )
                {
                    // If this request is a JComment - jump to the onJCommentsCommentBeforeAdd trigger
                    return;
                }
				
                // Passing login form.
                if(
	                $app->input->get->get('option') === 'com_users' &&
	                $app->input->get->get('view') === 'login'
				){
                    return;
                }
                
                // "MyMuse" module. Music e-store
                if(
                    $app->input->get('option') === 'com_mymuse' &&
                    $app->input->get('task') === 'confirm'
                ){
	                $post_info['comment_type'] = 'order';
				}
				if( ! isset( $post_info['comment_type'] ) )
					$post_info['comment_type'] = 'feedback_general_contact_form';
				
				$ctResponse = $this->ctSendRequest(
					'check_message', array(
						'sender_nickname' => $sender_nickname,
						'sender_email'    => $sender_email,
//						'message'         => trim(preg_replace("/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/", "\n", $message)),
						'message'         => $message,
						'post_info'       => json_encode($post_info),
					)
				);
				
				if ($ctResponse)
				{
					if (!empty($ctResponse) && is_array($ctResponse))
					{
						if ($ctResponse['errno'] != 0)
							$this->sendAdminEmail("CleanTalk. Can't verify feedback message!", $ctResponse['comment']);
						else
						{
							if ($ctResponse['allow'] == 0)
							{
								if ($app->input->get('option') == 'com_baforms')
								{
									echo '<input id="form-sys-mesage" type="hidden" value="' . htmlspecialchars($ctResponse['comment'], ENT_QUOTES) . '">';
									print "<script>var obj = { type : 'baform', msg : document.getElementById('form-sys-mesage').value }; window.parent.postMessage(obj, '*');</script>";
									die();
								}
								elseif (JFactory::getApplication()->input->get('option') == 'com_igallery' && JFactory::getApplication()->input->get('task') == 'imagefront.addComment')
								{
									$output = array(
										'success' => 0,
										'message' => $ctResponse['comment']
									);
									print json_encode($output);
									die();
								}
								elseif (JFactory::getApplication()->input->get('option') == 'com_contactenhanced' && JFactory::getApplication()->input->get('task') == 'contact.submit')
								{
									$output = array(
											'statusText' => strip_tags($ctResponse['comment']),
											'status' => 403
										);
									print json_encode($output);
									die();									
								}
								// JD Simple Contact Form ajax output
								elseif(
									JFactory::getApplication()->input->get('module') == 'jdsimplecontactform' &&
									JFactory::getApplication()->input->get('method') == 'submitForm' &&
									JFactory::getApplication()->input->get('option') == 'com_ajax'
								) {
									if( ! headers_sent() ) {
										header('Content-Type: application/json');
										header('Access-Control-Allow-Origin: *');
									}
									$return = array(
										'status' => '\O_o/',
										'message' => $ctResponse['comment'],
									);
									echo \json_encode($return);
									die();
								} elseif( $app->input->get('option') === 'com_sppagebuilder' ) {
									$output['status'] = false;
									$output['content'] = '<span class="sppb-text-danger">' . $ctResponse['comment'] . '</span>';
									echo \json_encode(
										array(
											'data' => \json_encode( $output ),
										)
									);
									die();
								}
								else
								{
									$error_tpl = file_get_contents(dirname(__FILE__) . "/lib/Cleantalk/Common/error.html");
									print str_replace('%ERROR_TEXT%', $ctResponse['comment'], $error_tpl);
									die();									
								}
							}
							elseif ($ctResponse['allow'] == 1 && ($this->params->get('form_protection') && in_array('check_external', $this->params->get('form_protection'))) && isset($_POST['ct_action'], $_POST['ct_method']) && strpos($_POST['ct_action'], 'paypal.com') === false)
							{
								$form_action = $_POST['ct_action'];
								$form_method = $_POST['ct_method'];
								unset($_POST['ct_action']);
								unset($_POST['ct_method']);
								print "<html><body><form method='$form_method' action='$form_action'>";
								CleantalkHelper::print_form($_POST, '');
								print "</form></body></html>";
								print "<script>
									if(document.forms[0].submit != 'undefined'){
										var objects = document.getElementsByName('submit');
										if(objects.length > 0)
											document.forms[0].removeChild(objects[0]);
									}
									document.forms[0].submit();
								</script>";
								die();
							}

						}
					}
				}
			}
		}


	}

	////////////////////////////
	// com_contact related sutff

    /**
     * onValidateContact trigger - used by com_contact
     * @access public
     *
     * @param &$contact
     * @param &$data
     *
     * @return Exception|void
     * @throws Exception
     * @since  1.5
     */
	public function onValidateContact(&$contact, &$data)
	{

		$session = JFactory::getSession();

		// constants can be found in components/com_contact/views/contact/tmpl/default_form.php
		// current higest version by default ('2.5' now)
		$user_name_key  = 'contact_name';
		$user_email_key = 'contact_email';
		$subject_key    = 'contact_subject';
		$message_key    = 'contact_message';

		$post_info['comment_type'] = 'feedback_general_contact_form';
		$post_info                 = json_encode($post_info);
		if ($post_info === false)
			$post_info = '';

		$ctResponse = self::ctSendRequest(
			'check_message', array(
				'sender_nickname' => $data[$user_name_key],
				'sender_email'    => $data[$user_email_key],
				'message'         => $data[$subject_key] . "\n " . $data[$message_key],
				'post_info'       => $post_info,
			)
		);
		if ($ctResponse)
		{
			$app = JFactory::getApplication();
			if (!empty($ctResponse) && is_array($ctResponse))
			{
				if ($ctResponse['errno'] != 0)
				{
					$this->sendAdminEmail("CleanTalk. Can't verify feedback message!", $ctResponse['comment']);
				}
				else
				{
					if ($ctResponse['allow'] == 0)
					{
						$res_str = $ctResponse['comment'];
						$app->setUserState('com_contact.contact.data', $data);  // not used in 1.5 :(
						$stub = JFactory::getApplication()->input->get('id');
						// Redirect back to the contact form.
						// see http://docs.joomla.org/JApplication::redirect/11.1 - what does last param mean?
						// but it works! AZ
						$app->redirect(JRoute::_('index.php?option=com_contact&view=contact&id=' . $stub, false), $res_str, 'error');

						return new Exception($res_str); // $res_str not used in com_contact code - see source :(
					}
				}
			}
		}

	}

	////////////////////////////
	// JComments related sutff

	/* List of available triggers in JComments 2.3.0 - jcomments.ajax.php

	  onJCommentsCaptchaVerify
	  onJCommentsCommentBeforeAdd	- used, working
	  onJCommentsCommentAfterAdd
	  onJCommentsCommentBeforeDelete
	  onJCommentsCommentAfterDelete	- used, but not called from comments admin panel
	  onJCommentsCommentBeforePublish - used, working
	  onJCommentsCommentAfterPublish
	  onJCommentsCommentBeforeChange
	  onJCommentsCommentAfterChange
	  onJCommentsCommentBeforeVote
	  onJCommentsCommentAfterVote
	  onJCommentsCommentBeforeReport
	  onJCommentsCommentAfterReport
	  onJCommentsUserBeforeBan
	  onJCommentsUserAfterBan

	 */

	/**
	 * onJCommentsFormAfterDisplay trigger
	 * @access public
	 * @return string html code to insert after JComments form (id="comments-form")
	 * @since  1.5
	 */
	public function onJCommentsFormAfterDisplay()
	{
		$this->JCReady = true;

		return null;
	}

	/**
	 * onJCommentsCommentBeforeAdd trigger
	 * @access public
	 *
	 * @param   JCommentsDB  $comment
	 *
	 * @return boolean
	 * @since  1.5
	 */
	public function onJCommentsCommentBeforeAdd(&$comment)
	{

		if (!$this->params->get('comments_and_messages') || !in_array('jcomments_check_comments', $this->params->get('comments_and_messages')))
			return true;
		
		$session = JFactory::getSession();

		// set new time because onJCommentsFormAfterDisplay worked only once
		// and formtime in session need to be renewed between ajax posts

		$post_info['comment_type'] = 'comment';
		$post_info['post_url']     = $session->get('cleantalk_current_page');
		$post_info                 = json_encode($post_info);
		if ($post_info === false)
		{
			$post_info = '';
		}

		$example = null;
		if ($this->params->get('comments_and_messages') && in_array('jcomments_relevance_test', $this->params->get('comments_and_messages')))
		{
			switch ($comment->object_group)
			{
				case 'com_content':
					$article = JTable::getInstance('content');
					$article->load($comment->object_id);
					$baseText = $article->introtext . '<br>' . $article->fulltext;
					break;
				default:
					$baseText = '';
			}

			$db    = JCommentsFactory::getDBO();
			$query = "SELECT comment "
				. "\nFROM #__jcomments "
				. "\nWHERE published = 1 "
				. "\n  AND object_group = '" . $db->getEscaped($comment->object_group) . "'"
				. "\n  AND object_id = " . $comment->object_id
				. (JCommentsMultilingual::isEnabled() ? "\nAND lang = '" . JCommentsMultilingual::getLanguage() . "'" : "")
				. " ORDER BY id DESC "
				. " LIMIT 10 ";
			$db->setQuery($query);
			$prevComments = $db->loadResultArray();
			$prevComments = $prevComments == null ? '' : implode("\n\n", $prevComments);

			$example = $baseText . "\n\n\n\n" . $prevComments;
		}

		$ctResponse = self::ctSendRequest(
			'check_message', array(
				'example'         => $example,
				'message'         => preg_replace('/\s+/', ' ', str_replace("<br />", " ", $comment->comment)),
				'sender_nickname' => $comment->name,
				'sender_email'    => $comment->email,
				'post_info'       => $post_info,
			)
		);
		if ($ctResponse)
		{
			if (!empty($ctResponse) && is_array($ctResponse))
			{
				if ($ctResponse['allow'] == 0)
				{
					if ($this->params->get('comments_and_messages') && in_array('jcomments_unpublished_nofications', $this->params->get('comments_and_messages')))
					{
						JComments::sendNotification($comment, true);
					}
					if ($ctResponse['stop_queue'] === 1 || ($this->params->get('comments_and_messages') && !in_array('jcomments_automod', $this->params->get('comments_and_messages'))) || !$this->params->get('comments_and_messages'))
					{
						JCommentsAJAX::showErrorMessage($ctResponse['comment'], 'comment');

						return false;
					}
					$comment->published = false;

				} else {
					if ($ctResponse['stop_words'] === 1) {
						$comment->published = false;
					}
				}
			}

		}

		return true;
	}

	////////////////////////////
	// Private methods

	/**
	 * Include in head adn fill form
	 *
	 * @param   type  $form_id
	 * @param   type  $data
	 *
	 * @return string
	 */
	private function fillRegisterFormScriptHTML($form_id, $data = null, $onLoad = true)
	{
		if ($data === null)
		{
			$session = JFactory::getSession();
			$data    = $session->get('ct_register_form_data');
		}

		$str = "\n";

		// setTimeout to fill form under Joomla 1.5
		$str .= 'window.onload = window.setTimeout(\'fillHide()\', 1000); function fillHide() {';

		$str .= 'form = document.getElementById("' . $form_id . '");' . "\n";
		$str .= 'if(form){' . "\n";
		if (!empty($data))
		{
			foreach ($data as $key => $val)
			{

				// Skip data for JavaScript test
				if (preg_match('/^ct_checkjs/', $key))
					continue;

				if (is_array($val))
				{
					foreach ($val as $_key => $_val)
					{
						if (is_array($_val))
						{
							continue;
						}

						$str .= "\t" . 'if (document.getElementsByName("' . $key . '[' . $_key . ']")) {' . "\n";
						$str .= "\t\t" . 'if (document.getElementsByName("' . $key . '[' . $_key . ']")[0].type != "hidden") {' . "\n";
						$str .= "\t\t\t" . 'document.getElementsByName("' . $key . '[' . $_key . ']")[0].value = "' . $_val . '"' . "\n";
						$str .= "\t\t } \n";
						$str .= "\t } \n";
					}
				}
				else
				{
					$str .= "\t" . 'if (document.getElementsByName("' . $key . '")) {' . "\n";
					$str .= "\t\t" . 'if (document.getElementsByName("' . $key . '")[0].type != "hidden") {' . "\n";
					$str .= "\t\t\t" . 'document.getElementsByName("' . $key . '")[0].value = "' . $val . '"' . "\n";
					$str .= "\t\t } \n";
					$str .= "\t } \n";
				}
			}
		}
		$str .= '}' . "\n";
		$str .= '}' . "\n";

		return $str;
	}


    /**
     * Moderate new user
     * @return bool|void
     * @throws Exception
     */
	private function moderateUser()
	{

		// Call function only for guests
		// Call only for $_POST with variables
		if (
		    JFactory::getUser()->id ||
            $_SERVER['REQUEST_METHOD'] != 'POST' ||
            !$this->params->get('form_protection') ||
            !in_array('check_register', $this->params->get('form_protection')) ||
            JFactory::getApplication()->input->get('option') == 'com_easysocial'
        )
		{
			return false;
		}
		$post = $_POST;

		$post_name     = isset($post['name']) ? $post['name'] : (isset($post['jform']['name']) ? $post['jform']['name'] : null);
		$post_username = isset($post['username']) ? $post['username'] : (isset($post['jform']['username']) ? $post['jform']['username'] : null);
		$post_email    = isset($post['email']) ? $post['email'] : (isset($post['jform']['email1']) ? $post['jform']['email1'] : null);

		$session = JFactory::getSession();

		$ctResponse = self::ctSendRequest(
			'check_newuser', array(
				'sender_email'    => $post_email,
				'sender_nickname' => $post_username,
			)
		);
		if ($ctResponse)
		{
			if (!empty($ctResponse) && is_array($ctResponse))
			{
				if ($ctResponse['allow'] == 0)
				{
					if ($ctResponse['errno'] != 0)
					{
						$this->sendAdminEmail("CleanTalk plugin", $ctResponse['comment']);
					}
					else
					{
						// JoomShopping integration
						// @ToDo make it better
						$app = JFactory::getApplication();
						if( 'registersave' == $app->input->get('task') )
						{
							die($ctResponse['comment']);
						}
						$session->set('ct_register_form_data', $post);

						$app = JFactory::getApplication();
						$app->enqueueMessage($ctResponse['comment'], 'error');

						$uri      = JUri::getInstance();
						$redirect = $uri->toString();

						// OPC
						if (isset($_POST['return']))
						{
							$redirect_opc = base64_decode($_POST['return']);
							$u            =& JURI::getInstance($redirect);
							$u_opc        =& JURI::getInstance($redirect_opc);

							if ($u->getHost() == $u_opc->getHost())
							{
								$app->redirect(base64_decode($_POST['return']));
								die;
							}
						}

						$redirect = str_replace('?task=registration.register', '', $redirect);
						$app->redirect($redirect);
						die();
					}
				}
				else
				{
					$ct      = new Cleantalk();
					$comment = $ct->addCleantalkComment("", $ctResponse['comment']);
					$hash    = $ct->getCleantalkCommentHash($comment);

					$session->set('register_username', $post_username);
					$session->set('register_email', $post_email);
					$session->set('ct_request_id', $hash);
				}
			}
		}

	}


	private function sendAdminEmail($subject, $message, $is_html = false)
	{
		$app = JFactory::getApplication();

		$mail = JFactory::getMailer();
		$mail->addRecipient($app->getCfg('mailfrom'));
		$mail->setSender(array($app->getCfg('mailfrom'), $app->getCfg('fromname')));
		$mail->setSubject($subject);
		$mail->setBody($message);
		$mail->isHTML($is_html);
		$sent = $mail->Send();
	}

	private function ctSendFeedback($auth_key = '', $feedback_request = null)
	{
		if ($feedback_request)
		{
			$ct_request           = new CleantalkRequest();
			$ct_request->auth_key = $auth_key;
			$ct_request->feedback = $feedback_request;
			$ct                   = new Cleantalk();
			$ct->server_url       = 'https://moderate.cleantalk.org';
			$ct->work_url         = $this->params->get('work_url') ? $this->params->get('work_url') : '';
			$ct->server_ttl       = $this->params->get('server_ttl') ? $this->params->get('server_ttl') : 0;
			$ct->server_changed   = $this->params->get('server_changed') ? $this->params->get('server_changed') : 0;
			$ct->sendFeedback($ct_request);
			if ($ct->server_change)
				self::dbSetServer($ct->work_url, $ct->server_ttl, time());

			return true;
		}

		return false;
	}

    /**
     * Sending request to the cleantalk cloud
     *
     * @param $method
     * @param $params
     *
     * @return mixed|void|null
     *
     * @throws Exception
     * @since version
     */
    private function ctSendRequest($method, $params)
	{
		// URL Exclusions
		$url_check = true;
		$url_exclusion = $this->params->get('url_exclusions');
		if (! is_null( $url_exclusion ) && !empty( $url_exclusion ) )
		{
			$url_exclusion = explode(',', $url_exclusion);

			// Not always we have 'HTTP_X_REQUESTED_WITH' :(
			// @ToDo need to detect ajax request

			// @ToDo implement support for a regexp
			$check_type = 0;
			foreach ($url_exclusion as $key => $value) {
				if( $check_type == 1 ) { // If RegExp
					if( @preg_match( '/' . $value . '/', $_SERVER['REQUEST_URI'] ) ) {
						$url_check = false;
					}
				} else {
					if( strpos($_SERVER['HTTP_REFERER'], $value) !== false) { // Simple string checking
						$url_check = false;
					}
				}

			}
		}
		if (!$url_check)
			return;
		// END URL Exclusions

		// Roles Exclusions
		$roles = $this->params->get('roles_exclusions');
		if ( ! is_null( $roles ) ) {

			$set_check = true;

			foreach ($roles as $role_id) {
				if (self::_cleantalk_user_has_role_id($role_id)) {
					$set_check = false;
				}
			}

			if (!$set_check) {
				return;
			}
		}
		// END Roles Exclusions

		if ($this->params->get('ct_key_is_ok') && $this->params->get('ct_key_is_ok') == 0)
			return;
		
		//Skip backend or admin checking
		if (JFactory::getApplication()->isAdmin() || JFactory::getUser()->authorise('core.admin'))
			return;

		if ($this->params->get('data_processing') && in_array('skip_registered_users', $this->params->get('data_processing')) && !JFactory::getUser()->guest)
			return;

		$ct_request = new CleantalkRequest;

		foreach ($params as $k => $v)
		{
			$ct_request->$k = $v;
		}

		$ct_request->auth_key        = $this->params->get('apikey');
		$ct_request->agent           = self::ENGINE;
		$ct_request->submit_time     = $this->submit_time_test();
		$ct_request->sender_ip       = CleantalkHelper::ip__get(array('real'), false);
		$ct_request->x_forwarded_for = CleantalkHelper::ip__get(array('x_forwarded_for'), false);
		$ct_request->x_real_ip       = CleantalkHelper::ip__get(array('x_real_ip'), false);
		$ct_request->sender_info     = $this->get_sender_info();
		$ct_request->js_on           = $this->get_ct_checkjs($_COOKIE);

		$result             = null;
		$ct                 = new Cleantalk();
		$ct->server_url     = 'https://moderate.cleantalk.org';
		$ct->work_url       = $this->params->get('work_url') ? $this->params->get('work_url') : '';
		$ct->server_ttl     = $this->params->get('server_ttl') ? $this->params->get('server_ttl') : 0;
		$ct->server_changed = $this->params->get('server_changed') ? $this->params->get('server_changed') : 0;

		switch ($method)
		{
			case 'check_message':
				$result = $ct->isAllowMessage($ct_request);
				break;
			case 'send_feedback':
				$result = $ct->sendFeedback($ct_request);
				break;
			case 'check_newuser':
				$result = $ct->isAllowUser($ct_request);
				break;
			default:
				return null;
		}

		if ($ct->server_change)
		{
			self::dbSetServer($ct->work_url, $ct->server_ttl, time());
		}
		// Result should be an 	associative array
		$result = json_decode(json_encode($result), true);

		$connection_reports = $this->params->get('connection_reports') ? json_decode(json_encode($this->params->get('connection_reports')), true) : array('success' => 0, 'negative' => 0, 'negative_report' => null);
		if (isset($result['errno']) && intval($result['errno']) !== 0 && intval($ct_request->js_on) == 1)
		{
			$result['allow'] = 1;
			$result['errno'] = 0;
			$connection_reports['negative']++;
			if (isset($result['errstr']))
				$connection_reports['negative_report'][] = array('date' => date("Y-m-d H:i:s"), 'page_url' => $_SERVER['REQUEST_URI'], 'lib_report' => $result['errstr']);
		}
		if (isset($result['errno']) && intval($result['errno']) !== 0 && intval($ct_request->js_on) != 1)
		{
			$result['allow']      = 0;
			$result['spam']       = 1;
			$result['stop_queue'] = 1;
			$result['comment']    = 'Forbidden. Please, enable Javascript.';
			$result['errno']      = 0;
			$connection_reports['negative']++;
		}
		if (isset($result['errno']) && intval($result['errno']) === 0 && $result['errstr'] == '')
			$connection_reports['success']++;

		$save_params['connection_reports'] = $connection_reports;
		$this->saveCTConfig($save_params);

		return $result;
	}

	/**
	 * Current server setter
	 * $ct_work_url
	 * $ct_server_ttl
	 * $ct_server_changed
	 * @return null
	 */
	private function dbSetServer($ct_work_url, $ct_server_ttl, $ct_server_changed)
	{
		$save_params['work_url']       = $ct_work_url;
		$save_params['server_ttl']     = $ct_server_ttl;
		$save_params['server_changed'] = $ct_server_changed;

		$this->saveCTConfig($save_params);
	}

    /**
     * Get value of $ct_checkjs
     * JavaScript avaibility test.
     * @return null|0|1
     * @throws Exception
     */
	private function get_ct_checkjs($data)
	{

		if (!$data)
			return;

		$checkjs       = null;
		$js_post_value = null;

		if (isset($data['ct_checkjs']))
		{
			$js_post_value = $data['ct_checkjs'];
			if ($this->params->get('js_keys'))
			{
				$keys    = json_decode(json_encode($this->params->get('js_keys')), true);
				$checkjs = isset($keys[$js_post_value]) ? 1 : 0;
			}
		}

		$option_cmd = JFactory::getApplication()->input->get('option');
		// Return null if ct_checkjs is not set, because VirtueMart not need strict JS test
		if (!isset($data['ct_checkjs']) && $option_cmd == 'com_virtuemart')
			$checkjs = null;

		return $checkjs;
	}

	/**
	 * Validate form submit time
	 *
	 */
	private function submit_time_test()
	{
		return $this->ct_cookies_test() ? time() - intval($this->ct_getcookie('apbct_timestamp')) : null;
	}

	/**
	 * Inner function - Default data array for senders
	 * @return array
	 */
	private function get_sender_info()
	{
		$page_set_timestamp  = (isset($_COOKIE['ct_ps_timestamp']) ? $_COOKIE['ct_ps_timestamp'] : 0);
		$js_timezone         = (isset($_COOKIE['ct_timezone']) ? $_COOKIE['ct_timezone'] : '');
		$first_key_timestamp = (isset($_COOKIE['ct_fkp_timestamp']) ? $_COOKIE['ct_fkp_timestamp'] : '');
		$pointer_data        = (isset($_COOKIE['ct_pointer_data']) ? json_decode($_COOKIE['ct_pointer_data']) : '');
		$get_cms_tag         = explode('-', JFactory::getLanguage()->getTag());
		$cms_lang            = ($get_cms_tag && is_array($get_cms_tag) && count($get_cms_tag) > 0) ? strtolower($get_cms_tag[0]) : '';
		$params = (array) $this->params;
		if (!isset($params['cookies'])) {
			$params['cookies'] = array('set_cookies' => 0, 'use_alternative_cookies' => 0);
		}

		$sender_info = array(
			'REFFERRER'              => (isset($_SERVER['HTTP_REFERER'])) ? htmlspecialchars((string) $_SERVER['HTTP_REFERER']) : null,
			'post_url'               => (isset($_SERVER['HTTP_REFERER'])) ? htmlspecialchars((string) $_SERVER['HTTP_REFERER']) : null,
			'USER_AGENT'             => (isset($_SERVER['HTTP_USER_AGENT'])) ? htmlspecialchars((string) $_SERVER['HTTP_USER_AGENT']) : null,
			'js_timezone'            => $js_timezone,
			'mouse_cursor_positions' => $pointer_data,
			'key_press_timestamp'    => $first_key_timestamp,
			'page_set_timestamp'     => $page_set_timestamp,
			'direct_post'            => $this->ct_direct_post,
			'cookies_enabled'        => $this->ct_cookies_test(),
			'ct_options'             => json_encode($params),
			'REFFERRER_PREVIOUS'     => $this->ct_getcookie('apbct_prev_referer'),
			'fields_number'          => sizeof($_POST),
			'cms_lang'               => $cms_lang,
			'apbct_visible_fields'   => !empty($_COOKIE['ct_visible_fields']) ? $this->ct_visibile_fields__process($_COOKIE['ct_visible_fields'])  : null,
		);

		return json_encode($sender_info);
	}

	/**
	 * Process visible fields for specific form to match the fields from request
	 * 
	 * @param string $visible_fields
	 * 
	 * @return string
	 */
	function ct_visibile_fields__process($visible_fields) {
	    if(strpos($visible_fields, 'wpforms') !== false){
			$visible_fields = preg_replace(
				array('/\[/', '/\]/'),
				'',
				str_replace(
					'][',
					'_',
					str_replace(
						'wpforms[fields]',
						'',
						$visible_fields
					)
				)
			);
		}
		
		return $visible_fields;
	}

	/*
	 * Set Cookies test for cookie test
	 * Sets cookies with pararms timestamp && landing_timestamp && pervious_referer
	 * Sets test cookie with all other cookies
	 */
	private function ct_cookie()
	{
		if( ! $this->params->get('cookies') || ! in_array( 'set_cookies', $this->params->get('cookies')) || headers_sent() )
		{
			return;
		}
		else
		{
			// Cookie names to validate
			$cookie_test_value = array(
				'cookies_names' => array(),
				'check_value'   => $this->params->get('apikey'),
			);

			// Submit time
			$ct_timestamp = time();
			if( $this->params->get('cookies') && in_array('use_alternative_cookies', $this->params->get('cookies') ) ){
				// by database
				$prev_time = $this->ct_getcookie('apbct_prev_timestamp');
				if(is_null($prev_time)){
					$this->ct_setcookie('apbct_timestamp', $ct_timestamp);
					$this->ct_setcookie('apbct_prev_timestamp', $ct_timestamp);
					$cookie_test_value['check_value'] .= $ct_timestamp;
				} else {
					$this->ct_setcookie('apbct_timestamp', $prev_time);
					$this->ct_setcookie('apbct_prev_timestamp', $ct_timestamp);
					$cookie_test_value['check_value'] .= $prev_time;
				}
			} else {
				// by cookies
				$this->ct_setcookie('apbct_timestamp', $ct_timestamp);
				$cookie_test_value['cookies_names'][] = 'apbct_timestamp';
				$cookie_test_value['check_value'] .= $ct_timestamp;
			}

			// Pervious referer
			if (!empty($_SERVER['HTTP_REFERER']))
			{
				$this->ct_setcookie('apbct_prev_referer', $_SERVER['HTTP_REFERER']);
				$cookie_test_value['cookies_names'][] = 'apbct_prev_referer';
				$cookie_test_value['check_value']     .= $_SERVER['HTTP_REFERER'];
			}
			// Cookies test
			$cookie_test_value['check_value'] = md5($cookie_test_value['check_value']);
			$this->ct_setcookie('apbct_cookies_test', json_encode($cookie_test_value));
		}

	}

	/**
	 * Cookies test for sender
	 * @return null|0|1;
	 */
	private function ct_cookies_test()
	{
        if ($this->params->get('cookies') && ! in_array('set_cookies', $this->params->get('cookies') ) ) {
            return null;
        }
		if ($this->params->get('cookies') && in_array('use_alternative_cookies', $this->params->get('cookies') ) ) {
			return 1;
		}

		$cookie_test = json_decode(stripslashes(self::ct_getcookie('apbct_cookies_test')), true);

		if (is_null($cookie_test)) {
			return null;
		}
		$check_string = trim($this->params->get('apikey'));
		foreach ($cookie_test['cookies_names'] as $cookie_name) {
			$check_string .= self::ct_getcookie($cookie_name);
		}
		unset($cokie_name);

		if ($cookie_test['check_value'] == md5($check_string)) {
			return 1;
		} else {
			return 0;
		}
	}

	private function ct_setcookie( $name, $value )
	{
		if( $this->params->get('cookies') && in_array('use_alternative_cookies', $this->params->get('cookies') ) ) {

			self::_apbct_alt_sessions__remove_old();

			// To database
			$db = JFactory::getDbo();
			$query = $db->getQuery(true);

			$columns = array('id', 'name', 'value', 'last_update');
			$values = array($db->quote(self::_apbct_alt_session__id__get()), $db->quote($name), $db->quote($value), $db->quote(date('Y-m-d H:i:s')));
			$query
				->insert($db->quoteName('#__cleantalk_sessions'))
				->columns($db->quoteName($columns))
				->values(implode(',', $values));$db->setQuery($query . '  ON DUPLICATE KEY UPDATE ' . $db->quoteName('value') . ' = '.$db->quote($value).', ' . $db->quoteName('last_update') . ' = ' . $db->quote(date('Y-m-d H:i:s')));
			$db->execute();

		} else {
			// To cookies
			setcookie($name, $value, 0, '/');
		}
	}

	private function ct_getcookie( $name )
	{
		if ( $this->params->get('cookies') && in_array('use_alternative_cookies', $this->params->get('cookies') ) ) {

			// From database
			$db = JFactory::getDbo();
			$query = $db->getQuery(true);

			$query->select($db->quoteName(array('value')));
			$query->from($db->quoteName('#__cleantalk_sessions'));
			$query->where($db->quoteName('id') . ' = '. $db->quote(self::_apbct_alt_session__id__get()));
			$query->where($db->quoteName('name') . ' = '. $db->quote($name));
			$db->setQuery($query);
			$value = $db->loadResult();

			if ( ! is_null($value) ) {
				return $value;
			} else {
				return null;
			}

		} else {

			// From cookies
			if (isset($_COOKIE[$name])) {
				return $_COOKIE[$name];
			} else {
				return null;
			}

		}
	}

	/**
	 * Clean 'cleantalk_sessions' table
	 */
	static private function _apbct_alt_sessions__remove_old()
	{
		if (rand(0, 1000) < APBCT_SESSION__CHANCE_TO_CLEAN) {

			$db = JFactory::getDbo();
			$query = $db->getQuery(true);

			$query->delete($db->quoteName('#__cleantalk_sessions'));
			$query->where($db->quoteName('last_update') . ' < NOW() - INTERVAL '. APBCT_SESSION__LIVE_TIME .' SECOND');

			$db->setQuery($query);
			$db->execute();

		}
	}

	/**
	 * Get hash session ID
	 *
	 * @return string
	 */
	static private function _apbct_alt_session__id__get()
	{
		$id = CleantalkHelper::ip__get(array('real'))
			. filter_input(INPUT_SERVER, 'HTTP_USER_AGENT')
			. filter_input(INPUT_SERVER, 'HTTP_ACCEPT_LANGUAGE');
		return hash('sha256', $id);
	}

	private function get_spam_comments($offset = 0, $on_page = 20, $improved_check = false)
	{
		$db               = JFactory::getDBO();
		$output['result'] = null;
		$output['data']   = null;
		$data             = array();
		$spam_comments    = array();
		$db->setQuery("SHOW TABLES LIKE '%jcomments'");
		$improved_check = ($_POST['improved_check'] == 'true') ? true : false;
		$amount         = $on_page;
		$last_id        = $offset;
		$jtable         = $db->loadAssocList();
		if (empty($jtable))
		{
			$output['data']   = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_JCOMMENTSNOTINSTALLED');
			$output['result'] = 'error';
		}
		else
		{
			while (count($spam_comments) < $on_page)
			{
				if ($last_id > 0)
				{
					$offset = 0;
					$db->setQuery("SELECT * FROM `#__jcomments` WHERE id > " . $last_id . " LIMIT " . $offset . ", " . $amount);
				}
				$db->setQuery("SELECT * FROM `#__jcomments` LIMIT " . $offset . ", " . $amount);
				$comments = $db->loadAssocList();
				if (empty($comments))
					break;
				foreach ($comments as $comment)
				{
					if ($improved_check)
					{
						$curr_date          = (substr($comment['date'], 0, 10) ? substr($comment['date'], 0, 10) : '');
						$data[$curr_date][] = !empty($comment['ip']) ? $comment['ip'] : null;
						$data[$curr_date][] = !empty($comment['email']) ? $comment['email'] : null;
					}
					else
					{
						$data[] = !empty($comment['ip']) ? $comment['ip'] : null;
						$data[] = !empty($comment['email']) ? $comment['email'] : null;
					}

				}
				if (count($data) == 0)
				{
					$output['data']   = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_NOCOMMENTSTOCHECK');
					$output['result'] = 'error';
				}
				else
				{
					if ($improved_check)
					{
						foreach ($data as $date => $values)
						{
							$values = implode(',', $values);
							$result = CleantalkAPI::method__spam_check_cms($this->params->get('apikey'), $values, $date);
						}
					}
					else
					{
						$values = implode(',', $data);
						$result = CleantalkAPI::method__spam_check_cms($this->params->get('apikey'), $values);
					}
					if ($result)
					{
						if (isset($result['error_message']))
						{
							if ($result['error_message'] == 'Access key unset.' || $result['error_message'] == 'Unknown access key.')
								$output['data'] = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_BADKEY');
							elseif ($result['error_message'] == 'Service disabled, please go to Dashboard https://cleantalk.org/my?product_id=1')
								$output['data'] = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_BADKEY_DISABLED');
							elseif ($result['error_message'] == 'Calls limit exceeded, method name spam_check_cms().')
								$output['data'] = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CALLS_LIMIT_EXCEEDED');
							else $output['data'] = $result['error_message'];
							$output['result'] = 'error';
						}
						else
						{
							foreach ($result as $mail => $value)
							{
								if ($value['appears'] == '1')
								{
									foreach ($comments as $comment)
									{
										if (($comment['email'] == $mail || $comment['ip'] == $mail) && count($spam_comments) < $on_page)
											$spam_comments[] = $comment;

									}
								}
							}
						}
					}

				}
				$offset += $amount;
				$amount = $on_page - count($spam_comments);
				if (count($comments) < $on_page)
					break;
			}
			if ($output['result'] != 'error')
			{
				if (count($spam_comments) > 0)
				{
					$output['data']['spam_comments'] = $spam_comments;
					$output['result']                = 'success';
				}
				else
				{
					$output['data']   = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_NOCOMMENTSFOUND');
					$output['result'] = 'error';
				}
			}

		}

		return $output;
	}

	private function get_spam_users($offset = 0, $on_page = 20, $improved_check = false)
	{
		$db               = JFactory::getDBO();
		$data             = array();
		$spam_users       = array();
		$output['result'] = null;
		$output['data']   = null;
		$amount           = $on_page;
		$last_id          = $offset;
		while (count($spam_users) < $on_page)
		{
			if ($last_id > 0)
			{
				$offset = 0;
				$db->setQuery("SELECT * FROM `#__users` WHERE id > " . $last_id . " LIMIT " . $offset . ", " . $amount);
			}
			else $db->setQuery("SELECT * FROM `#__users` LIMIT " . $offset . ", " . $amount);
			$users = $db->loadAssocList();
			if (empty($users))
				break;
			foreach ($users as $user_index => $user)
			{
				if ($improved_check)
				{
					$curr_date          = (substr($user['registerDate'], 0, 10) ? substr($user['registerDate'], 0, 10) : '');
					$data[$curr_date][] = !empty($user['email']) ? $user['email'] : null;
				}
				else
					$data[] = !empty($user['email']) ? $user['email'] : null;

			}
			if (count($data) == 0)
			{
				$output['data']   = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_NOUSERSTOCHECK');
				$output['result'] = 'error';
			}
			else
			{

				if ($improved_check)
				{
					foreach ($data as $date => $values)
					{
						$values = implode(',', $values);
						$result = CleantalkAPI::method__spam_check_cms($this->params->get('apikey'), $values, $date);
					}
				}
				else
				{
					$values = implode(',', $data);
					$result = CleantalkAPI::method__spam_check_cms($this->params->get('apikey'), $values);
				}
				if ($result)
				{
					if (isset($result['error_message']))
					{
						if ($result['error_message'] == 'Access key unset.' || $result['error_message'] == 'Unknown access key.')
							$output['data'] = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_BADKEY');
						elseif ($result['error_message'] == 'Service disabled, please go to Dashboard https://cleantalk.org/my?product_id=1')
							$output['data'] = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_BADKEY_DISABLED');
						elseif ($result['error_message'] == 'Calls limit exceeded, method name spam_check_cms().')
							$output['data'] = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CALLS_LIMIT_EXCEEDED');
						else $output['data'] = $result['error_message'];
						$output['result'] = 'error';
					}
					else
					{
						foreach ($result as $mail => $value)
						{
							if ($value['appears'] == '1')
							{
								foreach ($users as $user)
								{
									if ($user['email'] == $mail && count($spam_users) < $on_page)
									{
										if ($user['lastvisitDate'] == '0000-00-00 00:00:00')
											$user['lastvisitDate'] = '-';
										$spam_users[] = $user;
									}
								}
							}
						}
					}
				}


			}
			$offset += $amount;
			$amount = $on_page - count($spam_users);
			if (count($users) < $on_page)
				break;
		}
		if ($output['result'] != 'error')
		{
			if (count($spam_users) > 0)
			{
				$output['data']['spam_users'] = $spam_users;
				$output['result']             = 'success';
			}
			else
			{
				$output['data']   = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_NOUSERSFOUND');
				$output['result'] = 'error';
			}
		}

		return $output;
	}

	private function sfw_check()
	{
		$app = JFactory::getApplication();

		if (!$app->isAdmin() && $this->params->get('other_settings') && in_array('sfw_enable', $this->params->get('other_settings')) && $_SERVER["REQUEST_METHOD"] == 'GET')
		{
	        $firewall = new Firewall(
	            $this->params->get('apikey'),
	            DB::getInstance(),
	            APBCT_TBL_FIREWALL_LOG
	        );
	        $firewall->loadFwModule( new SFW(
	            APBCT_TBL_FIREWALL_DATA,
	            array(
	                'sfw_counter'   => 0,
	                'cookie_domain' => Server::get('HTTP_HOST'),
	                'set_cookies'    => $this->params->get('cookies'),
	            )
	        ) );

	        $firewall->run();

	        $this->apbct_run_cron();
		}
	}
	private function apbct_run_cron()
	{
	    $cron = new Cron();
	    $tasks_to_run = $cron->checkTasks(); // Check for current tasks. Drop tasks inner counters.
	    if(
	        ! empty( $tasks_to_run ) && // There is tasks to run
	        ! RemoteCalls::check() && // Do not doing CRON in remote call action
	        (
	            ! defined( 'DOING_CRON' ) ||
	            ( defined( 'DOING_CRON' ) && DOING_CRON !== true )
	        )
	    ){
	        $cron_res = $cron->runTasks( $tasks_to_run );
	        // Handle the $cron_res for errors here.
	    }
	}
	static public function apbct_sfw_update($access_key) {
	    if( empty( $access_key ) ){
	        return false;
	    }
        $firewall = new Firewall(
            $access_key,
            DB::getInstance(),
            APBCT_TBL_FIREWALL_LOG
        );
        $firewall->setSpecificHelper( new CleantalkHelper() );
        $fw_updater = $firewall->getUpdater( APBCT_TBL_FIREWALL_DATA );
        $fw_updater->update();
	    
	}
	static public function apbct_sfw_send_logs($access_key) {
	    if( empty( $access_key ) ){
	        return false;
	    }

        $firewall = new Firewall( $access_key, DB::getInstance(), APBCT_TBL_FIREWALL_LOG );
		$firewall->setSpecificHelper( new CleantalkHelper() );
        $result = $firewall->sendLogs();

        return true;
	}
	private function saveCTConfig($params)
	{
		if (count($params) > 0)
		{
			$table = JTable::getInstance('extension');
			$table->load($this->_id);
			$jparams = new JRegistry($table->params);
			foreach ($params as $k => $v)
				$jparams->set($k, $v);
			$table->params = $jparams->toString();
			$table->store();
		}
	}

	static private function _cleantalk_user_has_role_id($role_id)
	{
		if (is_array(JFactory::getUser()->groups) && in_array($role_id, JFactory::getUser()->groups)) {
			return TRUE;
		}

		return FALSE;
	}

}
