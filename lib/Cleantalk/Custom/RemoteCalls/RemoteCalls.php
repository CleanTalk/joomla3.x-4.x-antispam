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
		),
		'private_record_add' => array(
			'last_call' => 0,
			'cooldown' => 0
		),
		'private_record_delete' => array(
			'last_call' => 0,
			'cooldown' => 0
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
     * Add private record to personal SFW table
     *
     * @return array
     */
    public function action__private_record_add()
    {
        $records = \Cleantalk\Common\Variables\Request::get('records');
        if ( empty($records) ) {
            return array('error' => 'PRIVATE_RECORD_ADD: No records provided');
        }

        $records = is_string($records) ? json_decode($records, true) : $records;
        if ( !is_array($records) ) {
            return array('error' => 'PRIVATE_RECORD_ADD: Records must be a valid JSON array');
        }

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = \Cleantalk\Common\Mloader\Mloader::get('Db');
        $db_obj = $db_class::getInstance();
        $table = $db_obj->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL;

        return \Cleantalk\Common\Firewall\Modules\Sfw::privateRecordsAdd($db_obj, $table, $records);
    }

    /**
     * Delete private record from personal SFW table
     *
     * @return array
     */
    public function action__private_record_delete()
    {
        $records = \Cleantalk\Common\Variables\Request::get('records');
        if ( empty($records) ) {
            return array('error' => 'PRIVATE_RECORD_DELETE: No records provided');
        }

        $records = is_string($records) ? json_decode($records, true) : $records;
        if ( !is_array($records) ) {
            return array('error' => 'PRIVATE_RECORD_DELETE: Records must be a valid JSON array');
        }

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = \Cleantalk\Common\Mloader\Mloader::get('Db');
        $db_obj = $db_class::getInstance();
        $table = $db_obj->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL;

        return \Cleantalk\Common\Firewall\Modules\Sfw::privateRecordsDelete($db_obj, $table, $records);
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