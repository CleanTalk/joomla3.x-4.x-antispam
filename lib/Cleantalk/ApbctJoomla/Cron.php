<?php

namespace Cleantalk\ApbctJoomla;

class Cron extends \Cleantalk\Common\Cron {

    public function saveTasks($tasks)
    {
        // TODO: Implement saveTasks() method.
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
            $jparams->set($this->cron_option_name, array('last_start' => time() , 'tasks' => $tasks));          
            $table->params = $jparams->toString();
            $table->store();
        }
    }

    /**
     * Getting all tasks
     *
     * @return array
     */
    public function getTasks()
    {
        // TODO: Implement getTasks() method.
        $plugin = \JPluginHelper::getPlugin('system', 'cleantalkantispam');
        $params = new \JRegistry($plugin->params);
        return isset($params[$this->cron_option_name]['tasks']) ? json_decode(json_encode($params[$this->cron_option_name]['tasks']),true) : null;
    }

    /**
     * Save option with tasks
     *
     * @return int timestamp
     */
    public function getCronLastStart()
    {
        // TODO: Implement getCronLastStart() method.
        $plugin = \JPluginHelper::getPlugin('system', 'cleantalkantispam');
        $params = new \JRegistry($plugin->params);
        return isset($params[$this->cron_option_name]['last_start']) ? $params[$this->cron_option_name]['last_start'] : 0;
    }

    /**
     * Save timestamp of running Cron.
     *
     * @return bool
     */
    public function setCronLastStart()
    {
        // TODO: Implement setCronLastStart() method.
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
            $jparams->set($this->cron_option_name, array('last_start' => time() , 'tasks' => $this->getTasks()));          
            $table->params = $jparams->toString();
            $table->store();
        }
    }
}