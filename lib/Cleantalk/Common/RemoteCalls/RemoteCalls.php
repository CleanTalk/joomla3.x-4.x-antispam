<?php

namespace Cleantalk\Common\RemoteCalls;

use Cleantalk\Common\RemoteCalls\Exceptions\RemoteCallsException;
use Cleantalk\Common\StorageHandler\StorageHandler;
use Cleantalk\Common\Variables\Request;

class RemoteCalls
{
    const COOLDOWN = 10;

    const OPTION_NAME = 'remote_calls';

    /**
     * @var string
     */
    protected $api_key;

    /**
     * @var array
     */
    protected $available_rc_actions;

    /**
     * @var bool
     */
    protected $rc_running;

    /**
     * For the testing purpose - mock the StorageHandler into this property
     * @var StorageHandler
     */
    public $storage_handler_class;

    public function __construct($api_key, StorageHandler $storage_handler_class)
    {
        $this->api_key = $api_key;
        $this->storage_handler_class = $storage_handler_class;
        $this->available_rc_actions = $this->getAvailableRcActions();
    }

    /**
     * @param $name
     * @return mixed
     * @psalm-taint-source input
     */
    public static function getVariable($name)
    {
        return Request::get($name);
    }

    /**
     * Checking if the current request is the Remote Call
     *
     * @return bool
     */
    public static function check()
    {
        return
            static::getVariable('spbc_remote_call_token') &&
            static::getVariable('spbc_remote_call_action') &&
            static::getVariable('plugin_name') &&
            in_array(static::getVariable('plugin_name'), array('antispam', 'anti-spam', 'apbct'));
    }

    /**
     * Execute corresponding method of RemoteCalls if exists
     *
     * @throws RemoteCallsException
     *
     * @return string
     */
    public function process()
    {
        $token = strtolower(static::getVariable('spbc_remote_call_token'));

        if ( $token !== strtolower(md5($this->api_key)) ) {
            throw new RemoteCallsException('WRONG_TOKEN');
        }

        $action = strtolower(static::getVariable('spbc_remote_call_action'));
        $actions = $this->available_rc_actions;

        if ( ! count($actions) ) {
            throw new RemoteCallsException('Available RC actions did not loaded.');
        }

        if ( ! array_key_exists($action, $actions) ) {
            throw new RemoteCallsException('Not available RC action was provided.');
        }

        // Return OK for test remote calls
        if ( static::getVariable('test') ) {
            return 'OK';
        }

        $cooldown = isset($actions[$action]['cooldown']) ? $actions[$action]['cooldown'] : self::COOLDOWN;

        if ( time() - $actions[$action]['last_call'] < $cooldown ) {
            throw new RemoteCallsException('TOO_MANY_ATTEMPTS');
        }

        $this->setLastCall($action);
        // Flag to let plugin know that Remote Call is running.
        $this->rc_running = true;

        $action_method = 'action__' . $action;

        if ( ! method_exists(static::class, $action_method) ) {
            throw new RemoteCallsException('UNKNOWN_ACTION_METHOD: ' . $action_method);
        }

        // Delay before perform action;
        if ( static::getVariable('delay') ) {
            sleep(static::getVariable('delay'));
        }

        try {
            $action_result = static::$action_method();

            // Supports old results returned an array ['error'=>'Error text']
            if ( $action_result['error'] ) {
                throw new RemoteCallsException($action_result['error']);
            }

            // @ToDo we can returning the RC result instead of simple 'OK'
            return 'OK';
        } catch ( \Exception $exception ) {
            throw new RemoteCallsException('RC result error: ' . $exception->getMessage());
        }
    }

    /**
     * Get available remote calls from the storage.
     *
     * @return array
     */
    protected function getAvailableRcActions()
    {
        $actions = $this->storage_handler_class->getSetting(static::OPTION_NAME);
        return $actions ?: $this->available_rc_actions;
    }

    /**
     * Set last call timestamp and save it to the storage.
     *
     * @param string $action
     * @return bool
     */
    protected function setLastCall($action)
    {
        $this->available_rc_actions[$action]['last_call'] = time();
        return $this->storage_handler_class->saveSetting(static::OPTION_NAME, $this->available_rc_actions);
    }

    /************************ Making Request Methods ************************/
    // @ToDo methods below must be replaced to the another class

    public static function getSiteUrl()
    {
        return (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://" . $_SERVER['HTTP_HOST'] . (isset($_SERVER['SCRIPT_URL']) ? $_SERVER['SCRIPT_URL'] : '');
    }

    public static function buildParameters($rc_action, $plugin_name, $api_key, $additional_params)
    {
        return array_merge(
            array(
                'spbc_remote_call_token' => md5($api_key),
                'spbc_remote_call_action' => $rc_action,
                'plugin_name' => $plugin_name,
            ),
            $additional_params
        );
    }

    /**
     * Performs remote call to the current website
     *
     * @param string $host
     * @param string $rc_action
     * @param string $plugin_name
     * @param string $api_key
     * @param array $params
     * @param array $patterns
     * @param bool $do_check Perform check before main remote call or not
     *
     * @return bool|string[]
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function perform($rc_action, $plugin_name, $api_key, $params, $patterns = array(), $do_check = true)
    {
        $host = static::getSiteUrl();
        $params = static::buildParameters($rc_action, $plugin_name, $api_key, $params);

        if ( $do_check ) {
            $result__rc_check_website = static::performTest($host, $params, $patterns);
            if ( !empty($result__rc_check_website['error']) ) {
                return $result__rc_check_website;
            }
        }

        $http = new \Cleantalk\Common\Http\Request();

        return $http
            ->setUrl($host)
            ->setData($params)
            ->setPresets($patterns)
            ->request();
    }

    /**
     * Performs test remote call to the current website
     * Expects 'OK' string as good response
     *
     * @param string $host
     * @param array $params
     * @param array $patterns
     *
     * @return array|bool|string
     */
    public static function performTest($host, $params, $patterns = array())
    {
        // Delete async pattern to get the result in this process
        $key = array_search('async', $patterns, true);
        if ( $key ) {
            unset($patterns[$key]);
        }

        // Adding test flag
        $params = array_merge($params, array('test' => 'test'));

        // Perform test request
        $http = new \Cleantalk\Common\Http\Request();
        $result = $http
            ->setUrl($host)
            ->setData($params)
            ->setPresets($patterns)
            ->request();

        // Considering empty response as error
        if ( $result === '' ) {
            $result = array('error' => 'WRONG_SITE_RESPONSE TEST ACTION : ' . $params['spbc_remote_call_action'] . ' ERROR: EMPTY_RESPONSE');
            // Wrap and pass error
        } elseif ( !empty($result['error']) ) {
            $result = array('error' => 'WRONG_SITE_RESPONSE TEST ACTION: ' . $params['spbc_remote_call_action'] . ' ERROR: ' . $result['error']);
            // Expects 'OK' string as good response otherwise - error
        } elseif ( is_string($result) && !preg_match('@^.*?OK$@', $result) ) {
            $result = array(
                'error' => 'WRONG_SITE_RESPONSE ACTION: '
                    . $params['spbc_remote_call_action']
                    . ' RESPONSE: '
                    . '"'
                    . htmlspecialchars(substr($result, 0, 400))
                    . '"'
            );
        }

        return $result;
    }
}
