<?php

namespace Cleantalk\ApbctJoomla;

class Helper extends \Cleantalk\Common\Helper\Helper {

    /**
     * Get fw stats from the storage.
     *
     * @return array
     * @example array( 'firewall_updating' => false, 'firewall_updating_id' => md5(), 'firewall_update_percent' => 0, 'firewall_updating_last_start' => 0 )
     * @important This method must be overloaded in the CMS-based Helper class.
     */
    public static function getFwStats()
    {
        //die( __METHOD__ . ' method must be overloaded in the CMS-based Helper class' );
        $plugin = \JPluginHelper::getPlugin('system', 'cleantalkantispam');
        $params = new \JRegistry($plugin->params);

        return array(
            'firewall_updating_id' => $params->get('firewall_updating_id'),
            'firewall_updating_last_start' => $params->get('firewall_updating_last_start', 0),
            'firewall_update_percent' => $params->get('firewall_update_percent', 0)
        );
    }

    /**
     * Save fw stats on the storage.
     *
     * @param array $fw_stats
     * @return bool
     * @important This method must be overloaded in the CMS-based Helper class.
     */
    public static function setFwStats( $fw_stats )
    {
        $db = \JFactory::getDBO();

        $query = $db->getQuery(true);
        $query
            ->select($db->quoteName('extension_id'))
            ->from($db->quoteName('#__extensions'))
            ->where($db->quoteName('element') . ' = ' . $db->quote('cleantalkantispam'))
            ->where($db->quoteName('folder') . ' = ' . $db->quote('system'));
        $db->setQuery($query);
        $db->execute();

        if ($plg = $db->loadObject()) {
            $table = \JTable::getInstance('extension');
            $table->load((int) $plg->extension_id);
            $params = array();
            $params['firewall_updating_id'] = $fw_stats['firewall_updating_id'];
            $params['firewall_updating_last_start'] = $fw_stats['firewall_updating_last_start'];
            $params['firewall_update_percent'] = isset($fw_stats['firewall_update_percent']) ? $fw_stats['firewall_update_percent'] : 0;
            $jparams = new \JRegistry($table->params);
            foreach ($params as $k => $v)
                $jparams->set($k, $v);           
            $table->params = $jparams->toString();
            $table->store();
        }
    }

    /**
     * Implement here any actions after SFW updating finished.
     *
     * @return void
     */
    public static function SfwUpdate_DoFinisnAction()
    {
        $db = \JFactory::getDBO();

        $query = $db->getQuery(true);
        $query
            ->select($db->quoteName('extension_id'))
            ->from($db->quoteName('#__extensions'))
            ->where($db->quoteName('element') . ' = ' . $db->quote('cleantalkantispam'))
            ->where($db->quoteName('folder') . ' = ' . $db->quote('system'));
        $db->setQuery($query);
        $db->execute();

        if ($plg = $db->loadObject()) {
            $table = \JTable::getInstance('extension');
            $table->load((int) $plg->extension_id);
            $jparams = new \JRegistry($table->params);
            $jparams->set('sfw_last_check', time());                
            $table->params = $jparams->toString();
            $table->store();
        }
    }

	/**
	 * Wrapper for http_request
	 * Requesting HTTP response code for $url
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
	public static function http__request__get_response_code($url ){
		return static::httpRequest( $url, array(), 'get_code');
	}

	/**
	 * Wrapper for http_request
	 * Requesting data via HTTP request with GET method
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
	public static function http__request__get_content($url ){
		return static::httpRequest( $url, array(), 'get dont_split_to_array');
	}

	/**
	 * Do the remote call to the host.
	 *
	 * @param string $rc_action
	 * @param array $request_params
	 * @param array $patterns
	 * @return array|bool
	 * @todo Have to replace this method to the new class like HttpHelper
	 */
	public static function http__request__rc_to_host($rc_action, $request_params, $patterns = array() )
	{
		$request_params__default = array(
			'spbc_remote_call_action' => $rc_action,
			'plugin_name'             => 'apbct',
		);

		$result__rc_check_website = static::httpRequest(
			static::getSiteUrl(),
			array_merge( $request_params__default, $request_params, array( 'test' => 'test' ) ),
			array( 'get', 'dont_split_to_array' )
		);

		if( empty( $result__rc_check_website['error'] ) ){

			if (is_string($result__rc_check_website) && preg_match('@^.*?OK$@', $result__rc_check_website)) {

				static::httpRequest(
					static::getSiteUrl(),
					array_merge( $request_params__default, $request_params ),
					array_merge( array( 'get', ), $patterns )
				);

			}else
				return array(
					'error' => 'WRONG_SITE_RESPONSE ACTION: ' . $rc_action . ' RESPONSE: ' . htmlspecialchars( substr(
							! is_string( $result__rc_check_website )
								? print_r( $result__rc_check_website, true )
								: $result__rc_check_website,
							0,
							400
						) )
				);
		}else
			return array( 'error' => 'WRONG_SITE_RESPONSE TEST ACTION: ' . $rc_action . ' ERROR: ' . $result__rc_check_website['error'] );

		return true;
	}

	/**
	 * Get site url for remote calls.
	 *
	 * @return string@important This method can be overloaded in the CMS-based Helper class.
	 *
	 */
	private static function getSiteUrl()
	{
		return ( isset( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://" . $_SERVER['HTTP_HOST'] . ( isset($_SERVER['SCRIPT_URL'] ) ? $_SERVER['SCRIPT_URL'] : '' );
	}
}
