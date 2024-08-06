<?php

/**
 * CleanTalk joomla updater file
 *
 * @since         2.2
 * @package       Cleantalk
 * @subpackage    Joomla
 * @author        CleanTalk (welcome@cleantalk.org)
 * @copyright (C) 2021 СleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

defined('_JEXEC') or die('Restricted access');

//  Backward compatibility for Joomla versions from 5
if (defined('JVERSION')) {
    $currentVersion = substr(JVERSION, 0, 1);
    if ((int)$currentVersion >= 5) {
        JLoader::registerAlias('JFactory', '\\Joomla\\CMS\\Factory');
    }
}

class plgsystemcleantalkantispamInstallerScript
{
    public function preflight($type, $parent)
    {
    }

    public function install($parent)
    {
    }

    public function update($parent)
    {
    }

    public function postflight($type, $parent)
    {
		if ( $type === 'uninstall' ) {
			return;
		}

        // Updating roles_exclusion
        $excluded_roles = $this->getParam('roles_exclusions');

        if (is_array($excluded_roles)) {
            $default_roles = self::getGroups();
            $new_data_roles_excluded = array();

            foreach ($default_roles as $default_role) {
                if (in_array(strtolower($default_role->id), $excluded_roles)) {
                    $new_data_roles_excluded[] = strtolower($default_role->title);
                }
            }

            $params['roles_exclusions'] = implode(',', $new_data_roles_excluded);
            $this->setParams($params);
        }
    }


    public function uninstall($parent)
    {
    }

    /**
     * Get all user groups
     */
    static private function getGroups()
    {
        $db = JFactory::getDBO();

        $query = $db->getQuery(true);
        $query
            ->select(array('*'))
            ->from($db->quoteName('#__usergroups'));
        $db->setQuery($query);

        return $db->loadObjectList();
    }

    /*
	 * get a variable from the manifest file (actually, from the manifest cache).
	 */
    function getParam( $name ) {
        $db = JFactory::getDbo();
        $db->setQuery('SELECT params FROM #__extensions WHERE element = "cleantalkantispam"');
        $params = json_decode( $db->loadResult(), true );
        return $params[ $name ];
    }

    /*
     * sets parameter values in the component's row of the extension table
     */
    function setParams($param_array) {
        if ( count($param_array) > 0 ) {
            // read the existing component value(s)
            $db = JFactory::getDbo();
            $db->setQuery('SELECT params FROM #__extensions WHERE element = "cleantalkantispam"');
            $params = json_decode( $db->loadResult(), true );
            // add the new variable(s) to the existing one(s)
            foreach ( $param_array as $name => $value ) {
                $params[ (string) $name ] = (string) $value;
            }
            // store the combined new and existing values back as a JSON string
            $paramsString = json_encode( $params );
            $db->setQuery('UPDATE #__extensions SET params = ' .
                          $db->quote( $paramsString ) .
                          ' WHERE element = "cleantalkantispam"' );
            $db->query();
        }
    }
}
