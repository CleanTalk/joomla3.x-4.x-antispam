<?php

namespace Cleantalk\ApbctJoomla;

class Helper extends \Cleantalk\Common\Helper {

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
        return array('firewall_updating_id' => isset($params['firewall_updating_id']) ? $params['firewall_updating_id'] : null, 'firewall_updating_last_start' => isset($params['firewall_updating_last_start']) ? $params['firewall_updating_last_start'] : 0, 'firewall_update_percent' => isset($params['firewall_update_percent']) ? $params['firewall_update_percent'] : 0);
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
            $params['firewall_update_percent'] = 0;
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
}