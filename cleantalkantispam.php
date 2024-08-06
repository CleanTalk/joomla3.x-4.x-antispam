<?php

/**
 * CleanTalk joomla plugin
 *
 * @version       3.2.3
 * @package       Cleantalk
 * @subpackage    Joomla
 * @author        CleanTalk (welcome@cleantalk.org)
 * @copyright (C) 2016 Сleantalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

defined('_JEXEC') or die('Restricted access');

//  Backward compatibility for Joomla versions from 5
if (defined('JVERSION')) {
    $currentVersion = substr(JVERSION, 0, 1);
    if ((int)$currentVersion >= 5) {
        JLoader::registerAlias('JPlugin', '\\Joomla\\CMS\\Plugin\\CMSPlugin', '6.0');
        JLoader::registerAlias('JPluginHelper', '\\Joomla\\CMS\\Plugin\\PluginHelper');
        JLoader::registerAlias('JRegistry', '\\Joomla\\Registry\\Registry');
        JLoader::registerAlias('JFactory', '\\Joomla\\CMS\\Factory', '6.0');
        JLoader::registerAlias('JText', '\\Joomla\\CMS\\Language\\Text');
        JLoader::registerAlias('JHtml', '\\Joomla\\CMS\\HTML\\HTMLHelper');
        JLoader::registerAlias('JURI', '\\Joomla\\CMS\\Uri\\Uri');
        JLoader::registerAlias('JTable', '\\Joomla\\CMS\\Table\\Table');
    }
}

jimport('joomla.plugin.plugin');
jimport('joomla.application.application');
jimport('joomla.application.web');
jimport('joomla.application.component.helper');

// Sessions
define('APBCT_SESSION__LIVE_TIME', 86400*2);
define('APBCT_SESSION__CHANCE_TO_CLEAN', 100);

// Autoload
require_once(dirname(__FILE__) . '/lib/autoload.php');

//Antispam classes
use Cleantalk\Common\Antispam\Cleantalk;
use Cleantalk\Common\Antispam\CleantalkRequest;

use Cleantalk\Common\Cleaner\Sanitize;
use Cleantalk\Common\Mloader\Mloader;

use Cleantalk\Common\Variables\Server;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Session\Session;
use Joomla\CMS\Uri\Uri;

define('APBCT_TBL_FIREWALL_DATA', 'cleantalk_sfw');      // Table with firewall data.
define('APBCT_TBL_FIREWALL_LOG',  'cleantalk_sfw_logs'); // Table with firewall logs.
define('APBCT_TBL_AC_LOG',        'cleantalk_ac_log');   // Table with firewall logs.
define('APBCT_TBL_AC_UA_BL',      'cleantalk_ua_bl');    // Table with User-Agents blacklist.
define('APBCT_TBL_SESSIONS',      'cleantalk_sessions'); // Table with session data.
define('APBCT_SFW_SEND_LOGS_LIMIT', 1000);
define('APBCT_SPAMSCAN_LOGS',     'cleantalk_spamscan_logs'); // Table with session data.
define('APBCT_SELECT_LIMIT',      5000); // Select limit for logs.
define('APBCT_WRITE_LIMIT',       5000); // Write limit for firewall data.
define('APBCT_DIR_PATH',          __DIR__);
//define('APBCT_EXCLUSION_STRICT_MODE', true);

class plgSystemCleantalkantispam extends JPlugin
{
    /**
     * Plugin version string for server
     * @since         1.0
     */
    const ENGINE = 'joomla34-323';

    /**
     * Flag marked JComments form initialization.
     * @since         1.0
     */
    private $JCReady = false;

    /**
     * Days to hide trial notice banner
     */
    const DAYS_INTERVAL_HIDING_NOTICE = 30;

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
     * CMS version
     */
    public $cms_version;

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

        $this->cms_version = $this->getCmsVersion();

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
        /** @var \Cleantalk\Common\Helper\Helper $helper */
        $helper = Mloader::get('Helper');

        $api_key = trim($ct_api_key);

        if (($this->params->get('acc_status_last_check') && ($this->params->get('acc_status_last_check') < time() - 86400)) || $force_check || !$this->params->get('ct_key_is_ok'))
        {
            $ct_key_is_ok = 0;
            $key_is_valid = $helper::isApikeyCorrect($api_key);
            $save_params = array();
            $result = null;
            if ($key_is_valid){
                /** @var \Cleantalk\Common\Api\Api $api_class */
                $api_class = Mloader::get('Api');
                $result      = $api_class::methodNoticePaidTill($api_key, preg_replace('/http[s]?:\/\//', '', $_SERVER['HTTP_HOST'], 1));
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
     * Checking curl/allow_url_fopen availability
     */
    private function checkCurlAUFopenAvailability() {
        if(!function_exists('curl_init') && !ini_get('allow_url_fopen')) {
            return false;
        }

        return true;
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


        //cutting trims on early save
        //php 8.1 trim deprecated on null fixed
        if ( is_null($this->params->get('apikey')) ) {
            $apikey = '';
        } else {
            $apikey = trim($this->params->get('apikey'));
        }
        $save_params['apikey'] = $apikey;

        if (!$this->isAdmin())
        {
            // Remote calls
            /** @var \Cleantalk\Common\RemoteCalls\RemoteCalls $remote_calls_class */
            $remote_calls_class = Mloader::get('RemoteCalls');

            if( $remote_calls_class::check() ) {
                $rc = new $remote_calls_class( $apikey );
                $rc->process();
            }
        }

        if ($this->isAdmin() && $app->input->get('layout') == 'edit' && $app->input->get('extension_id') == $this->_id)
        {
            $output      = null;
            /** @var \Cleantalk\Common\Api\Api $api_class */
            $api_class = Mloader::get('Api');

            // Close review banner
            if (isset($_POST['ct_delete_notice']) && $_POST['ct_delete_notice'] === 'yes')
                $save_params['show_review_done'] = 1;

            // Getting key automatically
            if (isset($_POST['get_auto_key']) && $_POST['get_auto_key'] === 'yes')
            {
                $output = $api_class::methodGetApiKey('antispam', JFactory::getConfig()->get('mailfrom'), $_SERVER['HTTP_HOST'], 'joomla3');

	            if ( isset($output['account_exists']) && $output['account_exists'] == 1) {
		            $output['error_message'] = sprintf(
			            'Please, get the Access Key from %s CleanTalk Control Panel %s and insert it in the Access Key field',
			            '<a href="https://cleantalk.org/my/?cp_mode=antispam" target="_blank">',
			            '</a>'
		            );
	            }

                // Checks if the user token is empty, then get user token by notice_paid_till()
                if( empty( $output['user_token'] ) && ! empty( $output['auth_key'] ) ){

                    $result_tmp = $api_class::methodNoticePaidTill($output['auth_key'], preg_replace('/http[s]?:\/\//', '', $_SERVER['HTTP_HOST'], 1));

                    if( empty( $result_tmp['error'] ) )
                        $output['user_token'] = $result_tmp['user_token'];

                }
            }

            // Check spam comments
            if (isset($_POST['check_type']) && $_POST['check_type'] === 'comments')
            {
                $improved_check = ($_POST['improved_check'] === 'true') ? true : false;
                $offset         = isset($_POST['offset']) ? $_POST['offset'] : 0;
                $on_page        = isset($_POST['amount']) ? $_POST['amount'] : 2;
                $output         = $this->get_spam_comments($offset, $on_page, $improved_check);
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

            // Serve buttons
            if (isset($_POST['ct_serve_run_cron_sfw_send_logs']) && $_POST['ct_serve_run_cron_sfw_send_logs'] === 'yes') {
                /** @var \Cleantalk\Common\Cron\Cron $cron_class */
                $cron_class = Mloader::get('Cron');
                $cron_class = new $cron_class;
                $cron_class->serveCronActions('sfw_send_logs', time() + 120);
            }
            if (isset($_POST['ct_serve_run_cron_sfw_update']) && $_POST['ct_serve_run_cron_sfw_update'] === 'yes') {
                /** @var \Cleantalk\Common\Cron\Cron $cron_class */
                $cron_class = Mloader::get('Cron');
                $cron_class = new $cron_class;
                $cron_class->serveCronActions('sfw_update', time() + 120);
            }

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

                if (isset($new_config['ct_sfw_enable'])) {
                    self::apbct_sfw_update($access_key);
                    self::apbct_sfw_send_logs($access_key);
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
        $ctask_cmd  = JFactory::getApplication()->input->get('ctask');
        $post_field_stage  = JFactory::getApplication()->input->get('stage');
        $module_cmd = JFactory::getApplication()->input->get('module');
        $method_cmd = JFactory::getApplication()->input->get('method');

        if ((@$_GET['option'] == 'com_mijoshop' && @$_GET['route'] == 'api/customer') ||
            ($option_cmd == 'com_virtuemart' && $task_cmd == 'add') ||
            $option_cmd == 'com_jcomments' ||
            ($option_cmd == 'com_contact' && $task_cmd != 'contact.submit') ||
            $option_cmd == 'com_users' ||
            $option_cmd == 'com_user' ||
            $option_cmd == 'com_login' ||
            $option_cmd == 'com_akeebasubs' ||
            $option_cmd == 'com_jchat' ||
            $option_cmd == 'com_easysocial' ||
            ($module_cmd == 'shoutbox' && $method_cmd == 'getPosts') ||
            ($option_cmd == 'com_virtuemart' && $task_cmd == 'addJS') ||
            ($option_cmd == 'com_virtuemart' && $task_cmd == 'cart') ||
            ($option_cmd == 'com_rsform' && $task_cmd == 'ajaxValidate') || // RSFrom ajax validation on multipage form
            ($option_cmd == 'com_virtuemart' && !empty($ctask_cmd) && ($ctask_cmd !== 'savebtaddress' || empty($post_field_stage) || $post_field_stage !== 'final')) ||
            $option_cmd === 'com_civicrm'
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
        {
	        return $this->moderateUser();
        }

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
        if ($this->params->get('ct_tell_about_cleantalk') && strpos($_SERVER['REQUEST_URI'], '/administrator/') === false)
        {
            if ($this->params->get('spam_count') && $this->params->get('spam_count') > 0) {
	            $code = "
					<div id='cleantalk_footer_link' style='width:100%;text-align:center;'>
						<a href='https://cleantalk.org/joomla-anti-spam-plugin-without-captcha'>Anti-spam by CleanTalk</a> for Joomla!
						<br>" . $this->params->get('spam_count') . " spam blocked
					</div>";
            } else {
	            $code = "
					<div id='cleantalk_footer_link' style='width:100%;text-align:center;'>
						<a href='https://cleantalk.org/joomla-anti-spam-plugin-without-captcha'>Anti-spam by CleanTalk</a> for Joomla!
						<br>
					</div>";
            }

            $document_body = $this->getDocumentBody();

			// Joomla 3
			if ( strpos($document_body, "</footer>") !== false ) {
				$document_body = str_replace("</footer>", $code . " </footer>", $document_body);
			}

			// Joomla 5
	        if ( strpos($document_body, '<div class="site-grid">') !== false ) {
		        $document_body = str_replace("</body>", $code . " </body>", $document_body);
	        }

            $this->setDocumentBody($document_body);
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
        $urls     = $config->get('url_exclusions');
	    $current_page_url = ((!empty($_SERVER['HTTPS'])) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
		$session  = JFactory::getSession();
		$session->set('cleantalk_current_page', $current_page_url);

        if ($this->isSite() && ! $this->jot_cache_enabled() && !$this->pageExcluded($urls))
        {
            $this->sfw_check();
            $this->ct_cookie();
	        $type_of_cookie = $config->get('ct_use_alternative_cookies') || $config->get('ct_set_cookies') == 2
		        ? 'alt_cookies'
		        : 'simple_cookies';

	        // Add inline data
	        $document->addScriptDeclaration('
				const ctPublicData = {
					typeOfCookie: "' . $type_of_cookie . '"
				}
			');

            $document->addScript(JURI::root(true) . "/plugins/system/cleantalkantispam/js/ct-functions.js?" . time());

            // Bot detector
            if ($config->get('ct_use_bot_detector')) {
                $document->addScript("https://moderate.cleantalk.org/ct-bot-detector-wrapper.js");
            }

            $set_cookies = $this->params->get('ct_set_cookies') != 0 ;
            $document->addScriptDeclaration("var ct_setcookie = " . ($set_cookies ? 1 : 0)	 . ";");
            if ($set_cookies) {
                $document->addScriptDeclaration('ctSetCookie("ct_checkjs", "' . $this->cleantalk_get_checkjs_code() . '", "0");');
            }
            if ($config->get('ct_check_external'))
                $document->addScript(JURI::root(true) . "/plugins/system/cleantalkantispam/js/ct-external.js?" . time());
        }

        if ($user->get('isRoot'))
        {
            if ($this->isAdmin())
            {
                # Checking curl/allow_url_fopen availability
                $ct_curl_aufopen_availability = $this->checkCurlAUFopenAvailability();

                if ($config->get('apikey'))
                {
                    $result = $this->checkIsPaid($config->get('apikey'));
                }

                $ct_key_is_ok = 0;
                if (
                    ($config->get('ct_key_is_ok') && (int)$config->get('ct_key_is_ok') === 1) ||
                    (isset($result['ct_key_is_ok']) && (int)$result['ct_key_is_ok'] === 1)
                ) {
                    $ct_key_is_ok = 1;
                }
                $show_notice        = ($config->get('show_notice') && $config->get('show_notice') == 1) ? 1 : 0;
                $trial              = ($config->get('trial') && $config->get('trial') == 1) ? 1 : 0;
                $renew 				= ($config->get('renew') && $config->get('renew') == 1) ? 1 : 0;
                $ct_ip_license      = $config->get('ip_license') ? $config->get('ip_license') : 0;
                $ct_moderate_ip     = $config->get('moderate_ip') ? $config->get('moderate_ip') : 0;
                $ct_user_token      = $config->get('user_token') ? $config->get('user_token') : '';
                $ct_service_id      = $config->get('service_id') ? $config->get('service_id') : 0;
                $ct_account_name_ob = $config->get('account_name_ob') ? $config->get('account_name_ob') : '';
                $ct_account_name_ob = ! $ct_account_name_ob && isset($result['account_name_ob']) ? $result['account_name_ob'] : $ct_account_name_ob;

                if (!$ct_key_is_ok)
                    $notice = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_NOTICE_APIKEY');

                if ($show_notice == 1 && $trial == 1) {
                    if ( ! $this->isDismissedNotice('trial_' . $user->id) || $this->isPluginSettingsPage() ) {
                        $notice = JText::sprintf('PLG_SYSTEM_CLEANTALKANTISPAM_NOTICE_TRIAL', $config->get('user_token'));
                    }
                }

                if ($show_notice == 1 && $renew == 1)
                    if ( ! $this->isDismissedNotice('renew_' . $user->id) || $this->isPluginSettingsPage() ) {
                        $notice = JText::sprintf('PLG_SYSTEM_CLEANTALKANTISPAM_NOTICE_RENEW', $config->get('user_token'));
                    }

                if (!$ct_curl_aufopen_availability) {
                    $notice = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_NOTICE_CURL_AUFOPEN_UNAVAILABLE');
                }

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
						ct_extension_id = ' . $this->_id . ',

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
						ct_exclusions_common_notice = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_EXCLUSIONS_COMMON_NOTICE') . '",
						ct_exclusions_know_more = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_EXCLUSIONS_KNOW_MORE') . '",
						ct_spamcheck_checksusers = "' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_CHECKUSERS_LABEL') . '" // delete,
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
						ct_joomla_version = "' . $this->getCmsVersion() . '";
				');
                //Admin JS and CSS
	            if ( $app->input->get('layout') == 'edit' && $app->input->get('extension_id') == $this->_id ) {
		            JHtml::_('jquery.framework');
		            $document->addScript(JURI::root(true) . "/plugins/system/cleantalkantispam/js/ct-checkusers.js?" . time());
		            $document->addScript(JURI::root(true) . "/plugins/system/cleantalkantispam/js/ct-settings.js?" . time());
		            $document->addStyleSheet(JURI::root(true) . "/plugins/system/cleantalkantispam/css/ct-settings.css?" . time());
	            }

                if ($config->get('show_review') && $config->get('show_review') == 1 && $app->input->get('layout') == 'edit' && $app->input->get('extension_id') == $this->_id)
                {
                    $document->addScriptDeclaration('var ct_show_feedback=true;');
                    $document->addScriptDeclaration('var ct_show_feedback_mes="' . JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_FEEDBACKLINK') . '";');
                }
                else
                    $document->addScriptDeclaration('var ct_show_feedback=false;');

            }
            if (isset($notice)) {
                $notice_type = '';
                if ( $trial == 1 ) {
                    $notice_type = 'data-notice-type="trial"';
                }
                if ( $renew == 1 ) {
                    $notice_type = 'data-notice-type="renew"';
                }
                $notice = '<div id="apbct_joomla_notice" ' . $notice_type . '>' . $notice . '</div>';
                if(version_compare($this->cms_version, '4.0.0') >= 0) {
                    $app->getDocument()->addScriptOptions('joomla.messages', array('info' => array(array($notice))));
                } else {
                    JFactory::getApplication()->enqueueMessage($notice, 'notice');
                }
            }
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

        if (!$this->isSite()) {
            return;
        }
        $option_cmd = $app->input->get('option');
        $task_cmd   = $app->input->get('task');
        $ctask_cmd  = $app->input->get('ctask');
        $urls       = $this->params->get('url_exclusions');

        /**
         * Integration with JotCache Plugin
         */
        if ($this->jot_cache_enabled() && !$this->pageExcluded($urls))
        {
            $document = JFactory::getDocument();
            $config   = $this->params;
	        $type_of_cookie = $config->get('ct_use_alternative_cookies') || $config->get('ct_set_cookies') == 2
		        ? 'alt_cookies'
		        : 'simple_cookies';

	        // Add inline data
	        $document->addScriptDeclaration('
				const ctPublicData = {
					typeOfCookie: "' . $type_of_cookie . '"
				}
			');

            $this->sfw_check();
            $this->ct_cookie();
            $document->addScript(JURI::root(true) . "/plugins/system/cleantalkantispam/js/ct-functions.js?" . time());

            // Bot detector
            if ($config->get('ct_use_bot_detector')) {
                $document->addScript("https://moderate.cleantalk.org/ct-bot-detector-wrapper.js");
            }

            $set_cookies = $this->params->get('ct_set_cookies') != 0 ;
            $document->addScriptDeclaration("var ct_setcookie = " . ($set_cookies ? 1 : 0)	 . ";");
            $document->addScriptDeclaration('ctSetCookie("ct_checkjs", "' . $this->cleantalk_get_checkjs_code() . '", "0");');
            if ($config->get('ct_check_external'))
                $document->addScript(JURI::root(true) . "/plugins/system/cleantalkantispam/js/ct-external.js?" . time());
        }

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
                || $task_cmd == 'saveUser' // VirtueMart registration
            )
            {
                $this->moderateUser();
            }

        }
        if ($_SERVER['REQUEST_METHOD'] == 'GET')
        {
            if ($this->params->get('ct_check_search'))
            {
                if ( $option_cmd === 'com_search' && isset($_GET['searchword']) && $_GET['searchword'] !== '' ) // Search form
                {
                    $post_info['comment_type'] = 'site_search_joomla34';
                    $sender_email              = JFactory::getUser()->email;
                    $sender_nickname           = JFactory::getUser()->username;
                    $message                   = trim($_GET['searchword']);
                    $ctResponse                = $this->ctSendRequest(
                        'check_message',
                        array(
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
                                    $this->doBlockPage($ctResponse['comment']);

                                }
                            }
                        }
                    }
                }
            }
        }

		$isBreezingFormSubmit = $option_cmd === 'com_breezingforms' && $app->input->get('ff_task') === 'submit';

        if ($_SERVER['REQUEST_METHOD'] == 'POST' || $isBreezingFormSubmit)
        {
            $this->ct_direct_post = 1;
            /** @var \Cleantalk\Common\Helper\Helper $helper_class */
            $helper_class = Mloader::get('Helper');

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
            }elseif ($isBreezingFormSubmit){
                $ct_temp_msg_data = $helper_class::get_fields_any($_POST, $this->params->get('fields_exclusions'));

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
                $ct_temp_msg_data = $helper_class::get_fields_any($post_processed, $this->params->get('fields_exclusions'));
                $sender_email     = ($ct_temp_msg_data['email'] ? $ct_temp_msg_data['email'] : '');
                $sender_nickname  = ($ct_temp_msg_data['nickname'] ? $ct_temp_msg_data['nickname'] : '');
                $subject          = ($ct_temp_msg_data['subject'] ? $ct_temp_msg_data['subject'] : '');
                $contact_form     = ($ct_temp_msg_data['contact'] ? $ct_temp_msg_data['contact'] : true);
                $message          = ($ct_temp_msg_data['message'] ? $ct_temp_msg_data['message'] : array());

                if ($subject != '')
                    $message = array_merge(array('subject' => $subject), $message);
                $message = json_encode( $message );
            }
            // Creative Contact Form
            elseif ( $option_cmd === 'com_creativecontactform' && $app->input->get('view') === 'creativemailer' && $app->input->get('format') === 'raw' )
            {
                //Prepare data for checking
                $form_data = [];
                if ( $_POST['creativecontactform_fields'] ) {

                    foreach( $_POST['creativecontactform_fields'] as $element => $key ) {
                        $field_name = 'creativecontactform_fields' . '_' . $element . '_' . '0';
                        $form_data[$field_name] = $key[0];
                    }
                } else {
                    $form_data = $_POST;
                }

                $ct_temp_msg_data = $helper_class::get_fields_any($form_data, $this->params->get('fields_exclusions'));
                $sender_email     = $ct_temp_msg_data['email'] ?: '';
                $sender_nickname  = $ct_temp_msg_data['nickname'] ?: '';
                $subject          = $ct_temp_msg_data['subject'] ?: '';
                $message          = $ct_temp_msg_data['message'] ?: array();

                if ($subject !== '')
                {
                    $message = array_merge(array('subject' => $subject), $message);
                }
                $message = json_encode($message);
                $post_info['comment_type'] = 'contact_form_joomla_creative_contact_form';
            }
            // General test for any forms or form with custom fields
            else
            {
                $ct_temp_msg_data = $helper_class::get_fields_any($_POST, $this->params->get('fields_exclusions'));
                $sender_email     = ($ct_temp_msg_data['email'] ? $ct_temp_msg_data['email'] : '');
                $sender_nickname  = ($ct_temp_msg_data['nickname'] ? $ct_temp_msg_data['nickname'] : '');
                $subject          = ($ct_temp_msg_data['subject'] ? $ct_temp_msg_data['subject'] : '');
                //$contact_form     = ($ct_temp_msg_data['contact'] ? $ct_temp_msg_data['contact'] : true);
                $message          = ($ct_temp_msg_data['message'] ? $ct_temp_msg_data['message'] : array());

                if ($subject != '')
                    $message = array_merge(array('subject' => $subject), $message);
                $message = json_encode( $message );

            }

            // eShop integration
            if ( $option_cmd === 'com_eshop' ) {
                if ( $task_cmd === 'checkout.register' ) {
                    $this->moderateUser();
                } else {
                    // Skip catching any requests because have the direct integration.
                    //@see hook onAfterStoreOrder
                    //@see hook onAfterCompleteOrder
                    return;
                }
            }

            // JSN
            if ( isset($_POST['data']) && isset($_POST['data']['target_id']) && isset($_POST['data']['type']) ) {
                $sender_email    = JFactory::getUser()->email;
                $sender_nickname = JFactory::getUser()->username;
                $message         = isset($_POST['data']['message']) ? $_POST['data']['message'] : '';
                $post_info['comment_type'] = 'comment_form_joomla_jsn';
            }

            if (
                ! empty( $_POST ) &&
                ! $this->exceptionList() &&
                (
                    ! ( empty( $sender_email ) && ! $this->is_direct_integration($post_info) ) ||
                    ( $this->params->get( 'ct_check_all_post' ) )
                ) &&
                (
                    $this->params->get( 'ct_check_custom_contact_forms' ) ||
                    $this->params->get( 'ct_check_external' ) ||
                    $this->params->get( 'ct_check_contact_forms' )
                )
            ){
                if(
                    $task_cmd === 'registration.register' &&
                    $this->params->get('ct_check_register')
                )
                {
                    // If this request is a registration - jump to the onValidateContact trigger
                    return;
                }
                if(
                    $option_cmd === 'com_jcomments' &&
                    $this->params->get('ct_jcomments_check_comments')
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
                    'check_message',
                    array(
                        'sender_nickname' => $sender_nickname,
                        'sender_email'    => $sender_email,
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
                                } elseif (
                                    $app->input->get('option') === 'com_sppagebuilder' &&
                                    !isset($app->input->get('form')['formId'])
                                ) {
                                    $output['status'] = false;
                                    $output['content'] = '<span class="sppb-text-danger">' . $ctResponse['comment'] . '</span>';
                                    echo \json_encode(
                                        array(
                                            'data' => \json_encode( $output ),
                                        )
                                    );
                                    die();
                                } elseif (($option_cmd === 'com_virtuemart' && !empty($ctask_cmd) && $ctask_cmd === 'savebtaddress')) {
                                    echo \json_encode(
                                        array(
                                            'error' => 1,
                                            'msg' => $ctResponse['comment']
                                        )
                                    );
                                    die;
                                } elseif (($option_cmd === 'com_convertforms' && !empty($task_cmd) && $task_cmd === 'submit')) {
                                    echo \json_encode(
                                        array(
                                            'success' => false,
                                            'error' => $ctResponse['comment']
                                        )
                                    );
                                    die;
                                } elseif( $app->input->get('option') === 'com_komento' ) {
                                    echo \json_encode(
                                        array (
                                            0 =>
                                                array(
                                                    'type' => 'reject',
                                                    'data' =>
                                                        array (
                                                            0 => $ctResponse['comment'],
                                                        ),
                                                ),
                                        )
                                    );
                                    die();
                                }
                                //PWEB AJAX CONTACT FORMS integration
                                elseif (
                                    JFactory::getApplication()->input->get('module') == 'pwebcontact' &&
                                    JFactory::getApplication()->input->get('method') == 'sendEmail' &&
                                    JFactory::getApplication()->input->get('option') == 'com_ajax'
                                ) {
                                    $json_msg = array(
                                        'debug' => 'CAPTCHA check failed',
                                        'message' => $ctResponse['comment'],
                                        'success' => false
                                    );
                                    print json_encode($json_msg);
                                    die();
                                }
                                // Nice Page AJAX CONTACT FORMS integration
                                elseif (
                                    isset($_POST['ct_action'])
                                    && strpos($_POST['ct_action'], 'nicepagesrv') !== false
                                ) {
                                    $output['success'] = false;
                                    echo \json_encode($output);
                                    die();
                                }
                                elseif ( $post_info['comment_type'] === 'contact_form_joomla_creative_contact_form' )
                                {
                                    echo '[{"invalid":"problem_sending_email"}]';
                                    die();
                                }
                                else
                                {
                                    $this->doBlockPage($ctResponse['comment']);
                                }
                            }
                            elseif ($ctResponse['allow'] == 1 && $this->params->get('ct_check_external') && isset($_POST['ct_action'], $_POST['ct_method']) && strpos($_POST['ct_action'], 'paypal.com') === false)
                            {
                                // Nice Page AJAX CONTACT FORMS integration
                                if (
                                    isset($_POST['ct_action'])
                                    && strpos($_POST['ct_action'], 'nicepagesrv') !== false
                                ) {
                                    $output['success'] = true;
                                    echo \json_encode($output);
                                    die();
                                }

                                $form_action = $_POST['ct_action'];
                                $form_method = $_POST['ct_method'];
                                unset($_POST['ct_action']);
                                unset($_POST['ct_method']);
                                print "<html><body><form method='$form_method' action='$form_action'>";
                                $helper_class::print_form($_POST, '');
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

    /**
     * EShop integration
     * @param OrderEshop $orderRow
     *
     * @throws Exception
     */
    public function onAfterStoreOrder($orderRow)
    {
        $sender_nickname  = $orderRow->firstname;
        $sender_nickname .= $orderRow->lastname;
        $sender_email     = $orderRow->email;
        $message          = $orderRow->comment;
        $post_info['comment_type'] = 'contact_form_joomla_eshop__order';

        $ctResponse = $this->ctSendRequest(
            'check_message',
            array(
                'sender_nickname' => $sender_nickname,
                'sender_email'    => $sender_email,
                'message'         => $message,
                'post_info'       => json_encode($post_info),
            )
        );
        if ( isset($ctResponse['allow']) && $ctResponse['allow'] == 0  ) {
            $this->apbctEshopIsSpam = true;
            $this->apbctBlockComment = $ctResponse['comment'];
        }

    }

    /**
     * EShop integration
     * @param OrderEshop $orderRow
     *
     * @throws Exception
     */
    public function onAfterCompleteOrder($orderRow)
    {
        if ( $this->apbctEshopIsSpam ) {
            $row = JTable::getInstance('Eshop', 'Order');
            $id  = $orderRow->id;
            $row->load($id);
            $row->order_status_id = 1; // Set Order status "Cancelled"
            $row->comment = 'Get out!'; // Add CleanTalk block message to the comment
            $row->store();

            EshopHelper::updateInventory($row);

            $this->doBlockPage($this->apbctBlockComment);

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

		if ( is_object($data) ) {
			$sender_nickname = $data->user_name_key;
			$sender_email    = $data->user_email_key;
			$message         = $data->subject_key . "\n " . $data->message_key;
		} else {
			$sender_nickname = $data[$user_name_key];
            $sender_email    = $data[$user_email_key];
            $message         = $data[$subject_key] . "\n " . $data[$message_key];
		}

        $ctResponse = $this->ctSendRequest(
            'check_message',
            array(
                'sender_nickname' => $sender_nickname,
                'sender_email'    => $sender_email,
                'message'         => $message,
                'post_info'       => $post_info,
            )
        );
        if ($ctResponse)
        {
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
                        $this->doBlockPage($ctResponse['comment']);
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

        if (!$this->params->get('ct_jcomments_check_comments'))
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
        if ($this->params->get('ct_jcomments_relevance_test'))
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

        $ctResponse = $this->ctSendRequest(
            'check_message',
            array(
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
                    if ($this->params->get('ct_jcomments_unpublished_nofications'))
                    {
                        JComments::sendNotification($comment, true);
                    }
                    if ($ctResponse['stop_queue'] === 1 || !$this->params->get('ct_jcomments_automod'))
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

    /**
     * The spot to handle all ajax request for the plugin
     *
     * @return string[]|void
     *
     * @throws Exception
     * @since version
     */
    public function onAjaxCleantalkantispam() {
        Session::checkToken('get') or die(Text::_('JINVALID_TOKEN'));
        $data = Factory::getApplication()->input->json->getArray();
        if ( isset($data['action']) ) {
            switch ($data['action']) {
                case 'dismiss_notice' :
                    $this->setNoticeDismissed($data['data']);
                    // @ToDo add an error handling here
                    return ['success' => 'The notice dismissing was remembered'];
	            case 'usersChecker' :
		            $data['api_key'] = $this->params->get('apikey');
					$users_checker = new \Cleantalk\Custom\FindSpam\UsersChecker\UsersChecker($data);
					return $users_checker->getResponse();
	            case 'set_alt_cookies' :
		            self::_apbct_alt_sessions__remove_old();

		            // To database
		            $db = JFactory::getDbo();
		            $columns = array(
			            'id',
			            'name',
			            'value',
			            'last_update'
		            );
					$values = array();
		            $query = $db->getQuery(true);
		            $query->insert($db->quoteName('#__cleantalk_sessions'));
		            $query->columns($db->quoteName($columns));
					unset($data['action']);

					foreach ($data as $cookie_name => $cookie_value) {
						$values[] = implode(',', array(
							$db->quote(self::_apbct_alt_session__id__get()),
							$db->quote($cookie_name),
							$db->quote($cookie_value),
							$db->quote(date('Y-m-d H:i:s'))
						));
					}

		            $query->values($values);

		            $db->setQuery($query . '  ON DUPLICATE KEY UPDATE value=VALUES(value), last_update=VALUES(last_update);');
		            $db->execute();

		            return ('XHR OK');
	            case 'check_ajax':
                    $ctResponse = $this->ctSendRequest('check_newuser', array());

                    if ($ctResponse['allow'] == 0) {
                        return json_encode(['allow' => 0, 'msg' => $ctResponse['comment']]);
                    }

                    if ($ctResponse['allow'] == 1) {
                        return json_encode(['allow' => 1, 'msg' => '']);
                    }

                    return ['error' => 'Not working'];

                default :
                    return ['error' => 'Wrong action was provided'];
            }
        }
        return ['error' => 'No action was provided'];
    }

    ////////////////////////////
    // Private methods

    /**
     * Store the notice dismissed flag
     * @param array $notice_info
     */
    private function setNoticeDismissed($notice_info)
    {
        if ( ! isset($notice_info['notice_type']) ) {
            // @ToDo add an error throwing here
            return;
        }

        $filter = JFilterInput::getInstance();

        $user = Factory::getUser();
        $notice       = $filter->clean($notice_info['notice_type']);
        $uid          = $user->id;
        $notice_uid   = $notice . '_' . $uid;
        $current_date = time();

        $this->saveCTConfig(['cleantalk_' . $notice_uid . '_dismissed' => $current_date]);
    }

    /**
     * Check dismiss status of the notice
     *
     * @param string $notice_uid
     *
     * @return bool
     */
    private function isDismissedNotice($notice_uid)
    {
        $option_name = 'cleantalk_' . $notice_uid . '_dismissed';
        $notice_date_option = $this->params->get($option_name, false);

        if ( $notice_date_option === false ) {
            return false;
        }

        $current_time = time();
        $notice_time  = (int) $notice_date_option;

        if ( $current_time - $notice_time <= self::DAYS_INTERVAL_HIDING_NOTICE * 24 * 60 * 60 ) {
            return true;
        }

        return false;
    }

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
            !$this->params->get('ct_check_register') ||
            JFactory::getApplication()->input->get('option') === 'com_easysocial'
        )
        {
            return true;
        }
        $post = $_POST;

        $post_name     = isset($post['name']) ? $post['name'] : (isset($post['jform']['name']) ? $post['jform']['name'] : null);
        $post_username = isset($post['username']) ? $post['username'] : (isset($post['jform']['username']) ? $post['jform']['username'] : null);
        $post_email    = isset($post['email']) ? $post['email'] : (isset($post['jform']['email1']) ? $post['jform']['email1'] : null);

	    // Custom register plugin integration
		if (
			JFactory::getApplication()->input->get('option') === 'com_ajax' &&
			JFactory::getApplication()->input->get('plugin') === 'registration'
		) {
			$app = Factory::getApplication();
			$input = $app->input;
			$post_username = $input->get('name', '', "STRING");
			$post_email = $input->get('email', '', "filter");
		}

        $session = JFactory::getSession();

        $ctResponse = $this->ctSendRequest(
            'check_newuser',
            array(
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
                        $app = JFactory::getApplication();

                        if (
                            $app->input->get('option') === 'com_eshop' &&
                            $app->input->get('task') === 'checkout.register'
                        ) {
                            $out['error']['username'] = $ctResponse['comment'];
                            die(json_encode($out));
                        }
                        // JoomShopping integration
                        // @ToDo make it better
                        if( 'registersave' == $app->input->get('task') )
                        {
                            die($ctResponse['comment']);
                        }

						// Custom register plugin integration
	                    if(
		                    JFactory::getApplication()->input->get('option') === 'com_ajax' &&
		                    JFactory::getApplication()->input->get('plugin') === 'registration'
	                    )
	                    {
							return false;
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

                        if(version_compare($this->cms_version, '4.0.0') < 0) {
                            $redirect = str_replace('?task=registration.register', '', $redirect);
                        }

                        $app->redirect($redirect);
                        die();
                    }
                }
                else
                {
                    $session->set('register_username', $post_username);
                    $session->set('register_email', $post_email);
                    $session->set('ct_request_id', $ctResponse['id']);
					return true;
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
        static $executed_check = true;

        if ($executed_check) {

            $executed_check = false;
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
            $excluded_roles = $this->params->get('roles_exclusions');

            if ( is_string($excluded_roles) && !empty($excluded_roles) ) {
                $excluded_roles = explode(',', $excluded_roles);
                $excluded_roles = array_map(function ($element) {
                    return strtolower(trim($element));
                }, $excluded_roles);
                $default_roles = self::getGroups();
                $excluded_roles_ids = array();

                foreach ($default_roles as $default_role) {
                    if (in_array(strtolower($default_role->title), $excluded_roles)) {
                        $excluded_roles_ids[] = $default_role->id;
                    }
                }

                $set_check = true;

                foreach ($excluded_roles_ids as $role_id) {
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
	        if (
		        $this->isAdmin() ||
		        ( JFactory::getUser()->authorise('core.admin') && JFactory::getApplication()->input->get('option') !== 'com_ajax' )
	        )
	        {
		        return;
	        }

            if ($this->params->get('ct_skip_registered_users') && !JFactory::getUser()->guest)
                return;

            $ct_request = new CleantalkRequest;

            foreach ($params as $k => $v)
            {
                $ct_request->$k = $v;
            }

            /** @var \Cleantalk\Common\Helper\Helper $helper_class */
            $helper_class = Mloader::get('Helper');

            $ct_request->auth_key        = $this->params->get('apikey');
            $ct_request->agent           = self::ENGINE;
            $ct_request->submit_time     = $this->submit_time_test();
            $ct_request->sender_ip       = $helper_class::ipGet('real', false);
            $ct_request->x_forwarded_for = $helper_class::ipGet('x_forwarded_for', false);
            $ct_request->x_real_ip       = $helper_class::ipGet('x_real_ip', false);
            $ct_request->sender_info     = $this->get_sender_info();
            $ct_request->js_on           = $this->get_ct_checkjs($_COOKIE);
            $ct_request->event_token     = $this->getBotDetectorEventToken();

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
                $this->dbSetServer($ct->work_url, $ct->server_ttl, time());
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
        return false;
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
        {
            return;
        }

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
        if (!isset($data['ct_checkjs']) && $option_cmd === 'com_virtuemart')
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
     * @return false|string
     */
    private function get_sender_info()
    {
        $page_set_timestamp  = $this->ct_getcookie('ct_ps_timestamp');
        $js_timezone         = $this->ct_getcookie('ct_timezone');
        $first_key_timestamp = $this->ct_getcookie('ct_fkp_timestamp');
        $pointer_data        = $this->ct_getcookie('ct_pointer_data');
        $get_cms_tag         = explode('-', JFactory::getLanguage()->getTag());
        $cms_lang            = ($get_cms_tag && is_array($get_cms_tag) && count($get_cms_tag) > 0) ? strtolower($get_cms_tag[0]) : '';

        $params = $this->params->toArray();

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
            'apbct_visible_fields'   => $this->ct_visibile_fields__process($this->ct_getcookie('ct_visible_fields')),
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
        $visible_fields = !is_null($visible_fields) ? $visible_fields : '';
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
        if( ! $this->params->get('ct_set_cookies') || headers_sent() )
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
	        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
		        $apbct_timestamp = time();
		        $this->ct_setcookie('apbct_timestamp', (string)$apbct_timestamp);
		        $cookie_test_value['cookies_names'][] = 'apbct_timestamp';
		        $cookie_test_value['check_value']     .= $apbct_timestamp;
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
        if( ! $this->params->get('ct_set_cookies') || headers_sent() ) {
            return null;
        }
        if ( $this->params->get('ct_use_alternative_cookies') || $this->params->get('ct_set_cookies') == 2 ) {
            return 1;
        }
        if (isset($_COOKIE['apbct_cookies_test'])) {
            $cookie_test = json_decode(stripslashes($this->ct_getcookie('apbct_cookies_test')), true);

            if (is_null($cookie_test)) {
                return null;
            }
            $check_string = trim($this->params->get('apikey'));
            foreach ($cookie_test['cookies_names'] as $cookie_name) {
                $check_string .= $this->ct_getcookie($cookie_name);
            }
            unset($cokie_name);

            if ($cookie_test['check_value'] == md5($check_string)) {
                return 1;
            } else {
                return 0;
            }
        } else {
            return null;
        }
    }

    private function ct_setcookie( $name, $value )
    {
        if( $this->params->get('ct_use_alternative_cookies') || $this->params->get('ct_set_cookies') == 2 ) {

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
        if ( $this->params->get('ct_use_alternative_cookies') || $this->params->get('ct_set_cookies') == 2 ) {

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
        /** @var \Cleantalk\Common\Helper\Helper $helper_class */
        $helper_class = Mloader::get('Helper');

        $id = $helper_class::ipGet('real')
            . filter_input(INPUT_SERVER, 'HTTP_USER_AGENT')
            . filter_input(INPUT_SERVER, 'HTTP_ACCEPT_LANGUAGE');
        return hash('sha256', $id);
    }

    private function get_spam_comments($offset = 0, $on_page = 20, $improved_check = false)
    {
        $db               = JFactory::getDBO();
        $output['result'] = null;
        $output['data']   = null;
        $spam_comments    = array();
        $db->setQuery("SHOW TABLES LIKE '%jcomments'");
        $amount         = $on_page;
        $last_id        = $offset;
        $jtable         = $db->loadAssocList();

        /** @var \Cleantalk\Common\Api\Api $api_class */
        $api_class = Mloader::get('Api');

        if (empty($jtable))
        {
            $output['data']   = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_JCOMMENTSNOTINSTALLED');
            $output['result'] = 'error';
        }
        else
        {
            while (count($spam_comments) < $on_page)
            {
                $data = array();
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
                            $result = $api_class::methodSpamCheckCms($this->params->get('apikey'), $values, $date);
                        }
                    }
                    else
                    {
                        $values = implode(',', $data);
                        $result = $api_class::methodSpamCheckCms($this->params->get('apikey'), $values);
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
                                if (isset($value['appears']) && $value['appears'] == '1')
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

    private function sfw_check()
    {
        if (!$this->isAdmin() && $this->params->get('ct_sfw_enable') && $_SERVER["REQUEST_METHOD"] === 'GET')
        {
            $firewall = new \Cleantalk\Common\Firewall\Firewall(
                $this->params->get('apikey'),
                APBCT_TBL_FIREWALL_LOG
            );
            $firewall->loadFwModule( new \Cleantalk\Common\Firewall\Modules\Sfw(
                APBCT_TBL_FIREWALL_LOG,
                APBCT_TBL_FIREWALL_DATA,
                array(
                    'sfw_counter'   => 0,
                    'cookie_domain' => \Cleantalk\Common\Variables\Server::get('HTTP_HOST'),
                    'set_cookies'    => $this->params->get('ct_set_cookies') || $this->params->get('ct_use_alternative_cookies'),
                )
            ) );

            $firewall->run();

        }
        $this->apbct_run_cron();
    }
    private function apbct_run_cron()
    {
        /** @var \Cleantalk\Common\Cron\Cron $cron_class */
        $cron_class = Mloader::get('Cron');
        /** @var \Cleantalk\Common\RemoteCalls\RemoteCalls $rc_class */
        $rc_class = Mloader::get('RemoteCalls');

        $cron = new $cron_class();
        if (!$this->params->get($cron->getCronOptionName())) {
            $cron->addTask( 'sfw_update', '\plgSystemCleantalkantispam::apbct_sfw_update', 86400, time() + 60 );
            $cron->addTask( 'sfw_send_logs', '\plgSystemCleantalkantispam::apbct_sfw_send_logs', 3600 );
        }
        $tasks_to_run = $cron->checkTasks(); // Check for current tasks. Drop tasks inner counters.
        if(
            ! empty( $tasks_to_run ) && // There is tasks to run
            ! $rc_class::check() && // Do not doing CRON in remote call action
            (
                ! defined( 'DOING_CRON' ) ||
                ( defined( 'DOING_CRON' ) && DOING_CRON !== true )
            )
        ){
            $cron_res = $cron->runTasks( $tasks_to_run );
            // Handle the $cron_res for errors here.
        }
    }

    public static function apbct_sfw_update($access_key = '') {
        if( empty( $access_key ) ){
            $plugin = \JPluginHelper::getPlugin('system', 'cleantalkantispam');
            $params = new \JRegistry($plugin->params);
            $access_key = $params->get('apikey');
            if (empty($access_key)) {
                return false;
            }
        }

        $firewall = new \Cleantalk\Common\Firewall\Firewall(
            $access_key,
            APBCT_TBL_FIREWALL_LOG
        );

        return $firewall->getUpdater()->update();

    }

    public static function apbct_sfw_send_logs($access_key = '') {
        if( empty( $access_key ) ){
            $plugin = \JPluginHelper::getPlugin('system', 'cleantalkantispam');
            $params = new \JRegistry($plugin->params);
            $access_key = $params->get('apikey');
            if (empty($access_key)) {
                return false;
            }
        }

        $firewall = new \Cleantalk\Common\Firewall\Firewall( $access_key, APBCT_TBL_FIREWALL_LOG );
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
            foreach ($params as $k => $v){
                $jparams->set($k, $v);
            }
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

    /**
     * Get all user groups
     */
    private static function getGroups()
    {
        $db = JFactory::getDBO();

        $query = $db->getQuery(true);
        $query
            ->select(array('*'))
            ->from($db->quoteName('#__usergroups'));
        $db->setQuery($query);

        return $db->loadObjectList();
    }

    /**
     * Integration with JotCache
     *
     * @since 1.9
     */
    private function jot_cache_enabled() {
        if (JPluginHelper::isEnabled('system', 'jotcache')) {
            return true;
        }

        return false;
    }

    /**
     * isAdmin for 3-4 compatible
     */
    private function isAdmin() {
        $app = JFactory::getApplication();

        if(version_compare($this->cms_version, '4.0.0') >= 0) {
            return $app->isClient('administrator');
        }

        return $app->isAdmin();
    }

    /**
     * isSite for 3-4 compatible
     */
    private function isSite() {
        $app = JFactory::getApplication();

        if(version_compare($this->cms_version, '4.0.0') >= 0) {
            return $app->isClient('site');
        }

        return $app->isSite();
    }

    /**
     * Check version CMS
     */
    private function getCmsVersion () {

        $db = JFactory::getDbo();
        $query = $db->getQuery(true);

        // Select
        $query->select($db->quoteName('manifest_cache'));
        $query->from($db->quoteName('#__extensions'));
        $query->where($db->quoteName('name') . ' = ' . $db->quote('files_joomla'));

        $db->setQuery($query);

        $results = $db->loadAssoc();

        try {
            if($results && isset($results['manifest_cache'])) {
                $manifest_cache = json_decode($results['manifest_cache'], true);

                return $manifest_cache['version'];
            }
        } catch (\Exception $e) {}

        return '3.0.0';
    }

    /**
     * Get document body - compatible any version
     */
    public function getDocumentBody() {
        //3.0.0 - 3.1.9
        if(version_compare($this->cms_version, '3.2.0') < 0) {
            if(class_exists('JResponse')) {
                return JResponse::getBody();
            }
        }

        //3.2.0+
        if(version_compare($this->cms_version, '3.2.0') >= 0) {
            if(class_exists('JFactory')) {
                return JFactory::getApplication()->getBody();
            }
        }
    }

    /**
     * Set document body - compatible any version
     */
    public function setDocumentBody($body) {
        //3.0.0 - 3.1.9
        if(version_compare($this->cms_version, '3.2.0') < 0) {
            if(class_exists('JResponse')) {
                JResponse::setBody($body);
            }
        }

        //3.2.0+
        if(version_compare($this->cms_version, '3.2.0') >= 0) {
            if(class_exists('JFactory')) {
                JFactory::getApplication()->setBody($body);
            }
        }
    }

    /**
     * Check is the current page is the plugin settings page
     * @return bool
     *
     * @since version
     */
    private function isPluginSettingsPage() {
        $uri = Uri::getInstance();
        $layout = $uri->getVar('layout');
        $ext_id = $uri->getVar('extension_id');
        if ( isset($layout, $ext_id) && $layout === 'edit' && $ext_id == $this->_id ) {
            return true;
        }
        return false;
    }

    /**
     * Checking the page in the exception
     *
     * @param string $urls
     * @return boolean
     */
    public function pageExcluded($urls) {
        if (empty($urls)) {
            return false;
        }

        $_urls = explode(',', $urls);

        $current_page_url = ((!empty($_SERVER['HTTPS'])) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

        foreach ($_urls as $url) {
            // @ToDo need to detect ajax request
            // @ToDo implement support for a regexp
            if (defined('APBCT_EXCLUSION_STRICT_MODE') && APBCT_EXCLUSION_STRICT_MODE) {
                if ($current_page_url === $url) {
                    return true;
                }
            } else {
                if( strpos($current_page_url, $url) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    public function is_direct_integration($post_info)
    {
        return isset($post_info['comment_type']) && $post_info['comment_type'] !== 'feedback_general_contact_form';
    }

    private function doBlockPage($apbctBlockComment)
    {
        $ct_die_page = file_get_contents(Cleantalk::getLockPageFile());

        $message_title = '<b style="color: #49C73B;">Clean</b><b style="color: #349ebf;">Talk.</b> Spam protection';
        $back_script = '<script>setTimeout("history.back()", 5000);</script>';
        $back_link = '';
        if ( isset($_SERVER['HTTP_REFERER']) ) {
            $back_link = '<a href="' . Sanitize::cleanUrl(Server::get('HTTP_REFERER')) . '">Back</a>';
        }

        // Translation
        $replaces = array(
            '{MESSAGE_TITLE}' => $message_title,
            '{MESSAGE}'       => $apbctBlockComment,
            '{BACK_LINK}'     => $back_link,
            '{BACK_SCRIPT}'   => $back_script
        );

        foreach ( $replaces as $place_holder => $replace ) {
            $ct_die_page = str_replace($place_holder, $replace, $ct_die_page);
        }
        print $ct_die_page;
        die();
    }

    /**
     * Search for even_token in JFactory app POST data.
     * @return string
     * @throws Exception
     */
    public function getBotDetectorEventToken()
    {
        $app = JFactory::getApplication();
        $event_token = $app->input->get('ct_bot_detector_event_token');
        if ( empty($event_token) ){
            $get_input = $app->input->getArray();
            foreach ($get_input as $key => $value) {
                if (stripos($key, 'ct_bot_detector_event_token') === 0 &&
                    preg_match('/^[A-Fa-f0-9]{64}$/', $value)
                ) {
                    $event_token =  $value;
                }
            }
        }
        return empty($event_token) || !is_string($event_token) ? '' : $event_token;
    }
}
