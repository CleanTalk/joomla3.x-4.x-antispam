<?php

namespace Cleantalk\Common\RemoteCalls;

use Cleantalk\Common\Mloader\Mloader;
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

    public function __construct( $api_key )
    {
        $this->api_key = $api_key;
        $this->available_rc_actions = $this->getAvailableRcActions();
    }

    /**
     * Checking if the current request is the Remote Call
     *
     * @return bool
     */
    public static function check()
    {
        return
            Request::get( 'spbc_remote_call_token' ) &&
            Request::get( 'spbc_remote_call_action' ) &&
            Request::get( 'plugin_name' ) &&
            in_array( Request::get( 'plugin_name' ), array( 'antispam','anti-spam', 'apbct' ) );
    }

    /**
     * Execute corresponding method of RemoteCalls if exists
     *
     * @return void|string
     */
    public function process()
    {
        $action = strtolower( Request::get( 'spbc_remote_call_action' ) );
        $token  = strtolower( Request::get( 'spbc_remote_call_token' ) );

        $actions = $this->available_rc_actions;

        if( count( $actions ) !== 0 && array_key_exists( $action, $actions ) ){

            $cooldown = isset( $actions[$action]['cooldown'] ) ? $actions[$action]['cooldown'] : self::COOLDOWN;

            // Return OK for test remote calls
            if ( Request::get( 'test' ) ) {
                die('OK');
            }

            if( time() - $actions[ $action ]['last_call'] >= $cooldown ){

                $actions[$action]['last_call'] = time();

                $this->setLastCall($action);

                // Check API key
                if( $token === strtolower( md5( $this->api_key ) ) ){

                    // Flag to let plugin know that Remote Call is running.
                    $this->rc_running = true;

                    $action_method = 'action__' . $action;

                    if( method_exists( static::class, $action_method ) ){

                        // Delay before perform action;
                        if ( Request::get( 'delay' ) ) {
                            sleep(Request::get('delay'));
                        }

						try {
							$action_result = static::$action_method();

							$response = empty( $action_result['error'] )
								? 'OK'
								: 'FAIL ' . json_encode( array( 'error' => $action_result['error'] ) );

							if( ! Request::get( 'continue_execution' ) ){

								die( $response );

							}

							return $response;
						} catch ( \Exception $exception ) {
							error_log('RC error: ' . var_export($exception->getMessage(),1));
                            $out = 'FAIL '.json_encode(array('error' => $exception->getMessage()));
						}

                    }else
                        $out = 'FAIL '.json_encode(array('error' => 'UNKNOWN_ACTION_METHOD'));
                }else
                    $out = 'FAIL '.json_encode(array('error' => 'WRONG_TOKEN'));
            }else
                $out = 'FAIL '.json_encode(array('error' => 'TOO_MANY_ATTEMPTS'));
        }else
            $out = 'FAIL '.json_encode(array('error' => 'UNKNOWN_ACTION'));

        die( $out );
    }

    /**
     * Get available remote calls from the storage.
     *
     * @return array
     */
    protected function getAvailableRcActions()
    {
	    /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
	    $storage_handler_class = Mloader::get('StorageHandler');
        $actions = $storage_handler_class::getSetting(static::OPTION_NAME);
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
	    /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
	    $storage_handler_class = Mloader::get('StorageHandler');
        $this->available_rc_actions[$action]['last_call'] = time();
        return $storage_handler_class::saveSetting(static::OPTION_NAME, $this->available_rc_actions);
    }

	/************************ Making Request Methods ************************/

	public static function getSiteUrl()
	{
		return ( isset( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://" . $_SERVER['HTTP_HOST'] . ( isset($_SERVER['SCRIPT_URL'] ) ? $_SERVER['SCRIPT_URL'] : '' );
	}

	public static function buildParameters($rc_action, $plugin_name, $api_key, $additional_params)
	{
		return array_merge(
			array(
				'spbc_remote_call_token'  => md5($api_key),
				'spbc_remote_call_action' => $rc_action,
				'plugin_name'             => $plugin_name,
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
	 * @param array  $params
	 * @param array  $patterns
	 * @param bool   $do_check Perform check before main remote call or not
	 *
	 * @return bool|string[]
	 * @psalm-suppress PossiblyUnusedMethod
	 */
	public static function perform($rc_action, $plugin_name, $api_key, $params, $patterns = array(), $do_check = true)
	{
		$host = static::getSiteUrl();
		$params = static::buildParameters($rc_action, $plugin_name, $api_key, $params);

		if ($do_check) {
			$result__rc_check_website = static::performTest($host, $params, $patterns);
			if (! empty($result__rc_check_website['error'])) {
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
	 * @param array  $params
	 * @param array  $patterns
	 *
	 * @return array|bool|string
	 */
	public static function performTest($host, $params, $patterns = array())
	{
		// Delete async pattern to get the result in this process
		$key = array_search('async', $patterns, true);
		if ($key) {
			unset($patterns[$key]);
		}

		// Adding test flag
		$params = array_merge($params, array('test' => 'test'));

		// Perform test request
		$http   = new \Cleantalk\Common\Http\Request();
		$result = $http
			->setUrl($host)
			->setData($params)
			->setPresets($patterns)
			->request();

		// Considering empty response as error
		if ($result === '') {
			$result = array('error' => 'WRONG_SITE_RESPONSE TEST ACTION : ' . $params['spbc_remote_call_action'] . ' ERROR: EMPTY_RESPONSE');
			// Wrap and pass error
		} elseif (! empty($result['error'])) {
			$result = array('error' => 'WRONG_SITE_RESPONSE TEST ACTION: ' . $params['spbc_remote_call_action'] . ' ERROR: ' . $result['error']);
			// Expects 'OK' string as good response otherwise - error
		} elseif (is_string($result) && ! preg_match('@^.*?OK$@', $result)) {
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
