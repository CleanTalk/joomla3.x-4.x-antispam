<?php

namespace Cleantalk\Custom\RemoteCalls;

class RemoteCalls extends \Cleantalk\Common\RemoteCalls\RemoteCalls
{
	protected $available_rc_actions = array(
		'close_renew_banner' => array(
			'last_call' => 0,
			'cooldown' => self::COOLDOWN
		),
		'sfw_update' => array(
			'last_call' => 0,
			'cooldown' => 0
		),
		'sfw_send_logs' => array(
			'last_call' => 0,
			'cooldown' => self::COOLDOWN
		)
	);

    /**
     * SFW update
     *
     * @return string
     */
    public function action__sfw_update()
    {
        return \plgSystemCleantalkantispam::apbct_sfw_update( $this->api_key );
    }

    /**
     * SFW send logs
     *
     * @return string
     */
    public function action__sfw_send_logs()
    {
        return \plgSystemCleantalkantispam::apbct_sfw_send_logs( $this->api_key );
    }

    /**
     * Get available remote calls from the storage.
     *
     * @return array
     */
    /*protected function getAvailableRcActions()
    {
        $plugin = \JPluginHelper::getPlugin('system', 'cleantalkantispam');
        $params = new \JRegistry($plugin->params);
        $remote_calls = $params->get('remote_calls');
        return (!empty($remote_calls))
            ? json_decode(json_encode($remote_calls),true)
            : array(
                'close_renew_banner' => array(
                    'last_call' => 0,
                    'cooldown' => self::COOLDOWN
                ),
                'sfw_update' => array(
                    'last_call' => 0,
                    'cooldown' => 0
                ),
                'sfw_send_logs' => array(
                    'last_call' => 0,
                    'cooldown' => self::COOLDOWN
                )
            );
    }*/

    /**
     * Set last call timestamp and save it to the storage.
     *
     * @param array $action
     * @return void
     */
    /*protected function setLastCall( $action )
    {
        // TODO: Implement setLastCall() method.
        $remote_calls = $this->getAvailableRcActions();
        $remote_calls[$action]['last_call'] = time();
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
            $jparams->set('remote_calls', $remote_calls);          
            $table->params = $jparams->toString();
            $table->store();
        }
    }*/
}