<?php

namespace Cleantalk\Common;

class Schema
{
    /*
     * Array of schemas
     */
    private static $schemas = array(
        'sfw' => 'CREATE TABLE IF NOT EXISTS `%scleantalk_sfw` (
			`id` INT(11) NOT NULL AUTO_INCREMENT,
			`network` int(11) unsigned NOT NULL,
			`mask` int(11) unsigned NOT NULL,
			`status` TINYINT(1) NOT NULL DEFAULT 0,
			PRIMARY KEY (`id`),
			INDEX (  `network` ,  `mask` )
		    );',
        'ua_bl' => 'CREATE TABLE IF NOT EXISTS `%scleantalk_ua_bl` (
			`id` INT(11) NOT NULL,
			`ua_template` VARCHAR(255) NULL DEFAULT NULL,
			`ua_status` TINYINT(1) NULL DEFAULT NULL,
			PRIMARY KEY ( `id` ),
			INDEX ( `ua_template` )			
		    ) DEFAULT CHARSET=utf8;', // Don't remove the default charset!
        'sfw_logs' => 'CREATE TABLE IF NOT EXISTS `%scleantalk_sfw_logs` (
            `id` VARCHAR(40) NOT NULL,
            `ip` VARCHAR(15) NOT NULL,
            `status` ENUM(\'PASS_SFW\',\'DENY_SFW\',\'PASS_SFW__BY_WHITELIST\',\'PASS_SFW__BY_COOKIE\',\'DENY_ANTICRAWLER\',\'PASS_ANTICRAWLER\',\'DENY_ANTICRAWLER_UA\',\'PASS_ANTICRAWLER_UA\',\'DENY_ANTIFLOOD\',\'PASS_ANTIFLOOD\') NULL DEFAULT NULL,
            `all_entries` INT NOT NULL,
            `blocked_entries` INT NOT NULL,
            `entries_timestamp` INT NOT NULL,
            `ua_id` INT(11) NULL DEFAULT NULL,
            `ua_name` VARCHAR(1024) NOT NULL, 
            PRIMARY KEY (`id`));',
        'ac_logs' => 'CREATE TABLE IF NOT EXISTS `%scleantalk_ac_log` (
            `id` VARCHAR(40) NOT NULL,
            `ip` VARCHAR(40) NOT NULL,
            `ua` VARCHAR(40) NOT NULL,
            `entries` INT DEFAULT 0,
            `interval_start` INT NOT NULL,
            PRIMARY KEY (`id`));',
    );

    /**
     * @param null|string $table         Name of called table
     * @return array|string              Array of schemas or query string for selected scheme.
     * @throws \Exception                Throws if calling un-existed schema
     */
    public static function getSchema( $table = null )
    {
        if( is_null( $table ) ) {
            return self::$schemas;
        }

        if( array_key_exists( $table, self::$schemas ) ) {
            return self::$schemas[$table] ;
        }

        throw new \Exception( 'Called table scheme not exist.' );
    }

}