<?php

namespace Cleantalk\Common\RemoteCalls;

use Cleantalk\Common\Variables\Request;
use Cleantalk\Common\StorageHandler\StorageHandler;

class RemoteCalls
{

    const COOLDOWN = 10;

    const OPTION_NAME = 'remote_calls';

    /**
     * @var bool
     */
    private $rc_running;

    /**
     * @var string
     */
    protected $api_key;

    /**
     * @var array
     */
    private $available_rc_actions;

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
    public function perform()
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

                        $action_result = static::$action_method();

                        $response = empty( $action_result['error'] )
                            ? 'OK'
                            : 'FAIL ' . json_encode( array( 'error' => $action_result['error'] ) );

                        if( ! Request::get( 'continue_execution' ) ){

                            die( $response );

                        }

                        return $response;

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
        return StorageHandler::get(static::OPTION_NAME);
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
        return StorageHandler::set(static::OPTION_NAME, $this->available_rc_actions);
    }
}
