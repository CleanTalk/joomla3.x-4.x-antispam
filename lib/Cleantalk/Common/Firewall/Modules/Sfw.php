<?php

namespace Cleantalk\Common\Firewall\Modules;

use Cleantalk\Common\Firewall\Firewall;
use Cleantalk\Common\Helper\Helper;
use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Variables\Cookie;
use Cleantalk\Common\Variables\Get;
use Cleantalk\Common\Variables\Server;

#[\AllowDynamicProperties]
class Sfw extends \Cleantalk\Common\Firewall\FirewallModule
{
    public $module_name = 'SFW';

    private $test_status;
    private $blocked_ips = array();

    /**
     * @var string Content of the die page
     */
    private $sfw_die_page;

    /**
     * @var string|null
     */
    private $db__table__data;

    /**
     * @var string|null
     */
    private $db__table__logs;

    /**
     * FireWall_module constructor.
     * Use this method to prepare any data for the module working.
     *
     * @param string $log_table
     * @param string $data_table
     * @param $params
     */
    public function __construct($log_table, $data_table, $params = array())
    {
        parent::__construct($log_table, $data_table, $params);

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db = $db_class::getInstance();
        $this->db = $db;

        $this->db__table__data = $db->prefix . $data_table ?: null;
        $this->db__table__logs = $db->prefix . $log_table ?: null;

        foreach ( $params as $param_name => $param ) {
            $this->$param_name = isset($this->$param_name) ? $param : false;
        }

        $this->debug = (bool)static::getVariable('debug');
    }

    /**
     * @param $name
     * @return mixed
     * @psalm-taint-source input
     */
    public static function getVariable($name)
    {
        return Get::get($name);
    }

    /**
     * @inheritDoc
     */
    public function ipAppendAdditional(&$ips)
    {
        $this->real_ip = isset($ips['real']) ? $ips['real'] : null;
        $helper_class = $this->helper;

        if ( static::getVariable('sfw_test_ip') ) {
            if ( $helper_class::ipValidate(static::getVariable('sfw_test_ip')) !== false ) {
                $ips['sfw_test'] = static::getVariable('sfw_test_ip');
                $this->test_ip = htmlentities(static::getVariable('sfw_test_ip'), ENT_QUOTES);
                $this->test = true;
            }
        }
    }

    /**
     * Use this method to execute main logic of the module.
     *
     * @return array  Array of the check results
     */
    public function check()
    {
        $results = array();
        $status = 0;
        $helper_class = $this->helper;

        if ( $this->test ) {
            unset($_COOKIE['ct_sfw_pass_key']);
            Cookie::set('ct_sfw_pass_key', '0');
        }

        // Skip by cookie
        foreach ( $this->ip_array as $current_ip ) {
            if (
                Cookie::get('ct_sfw_pass_key')
                && strpos(Cookie::get('ct_sfw_pass_key'), md5($current_ip . $this->api_key)) === 0
            ) {
                if ( Cookie::get('ct_sfw_passed') ) {
                    if ( !headers_sent() ) {
                        Cookie::set(
                            'ct_sfw_passed',
                            '0',
                            time() + 86400 * 3,
                            '/',
                            '',
                            null,
                            true
                        );
                    } else {
                        $results[] = array(
                            'ip' => $current_ip,
                            'is_personal' => false,
                            'status' => 'PASS_SFW__BY_COOKIE'
                        );
                    }

                    // Do logging one passed request
                    $this->updateLog($current_ip, 'PASS_SFW');
                }

                if ( strlen(Cookie::get('ct_sfw_pass_key')) > 32 ) {
                    $status = substr(Cookie::get('ct_sfw_pass_key'), -1);
                }

                if ( $status ) {
                    $results[] = array(
                        'ip' => $current_ip,
                        'is_personal' => false,
                        'status' => 'PASS_SFW__BY_WHITELIST'
                    );
                }

                return $results;
            }
        }

        // Common check
        foreach ( $this->ip_array as $_origin => $current_ip ) {
            $current_ip_v4 = sprintf("%u", ip2long($current_ip));
            for ( $needles = array(), $m = 6; $m <= 32; $m++ ) {
                $mask = str_repeat('1', $m);
                $mask = str_pad($mask, 32, '0');
                $needles[] = sprintf("%u", bindec($mask & base_convert($current_ip_v4, 10, 2)));
            }
            $needles = array_unique($needles);

            $query = "SELECT
				network, mask, status, source
				FROM " . $this->db__table__data . "
				WHERE network IN (" . implode(',', $needles) . ")
				AND	network = " . $current_ip_v4 . " & mask 
				AND " . rand(1, 100000) . "  
				ORDER BY status DESC LIMIT 1";

            $db_results = $this->db->fetchAll($query);

            $test_status = 1;
            if ( !empty($db_results) ) {
                foreach ( $db_results as $db_result ) {
                    $result_entry = array(
                        'ip' => $current_ip,
                        'network' => $helper_class::ipLong2ip($db_result['network'])
                            . '/'
                            . $helper_class::ipMaskLongToNumber((int)$db_result['mask']),
                        'is_personal' => $db_result['source'],
                    );

                    if ( (int)$db_result['status'] === 1 ) {
                        $result_entry['status'] = 'PASS_SFW__BY_WHITELIST';
                        break;
                    }
                    if ( (int)$db_result['status'] === 0 ) {
                        $this->blocked_ips[] = $helper_class::ipLong2ip($db_result['network']);
                        $result_entry['status'] = 'DENY_SFW';
                    }

                    $test_status = (int)$db_result['status'];
                }
            } else {
                $result_entry = array(
                    'ip' => $current_ip,
                    'is_personal' => null,
                    'status' => 'PASS_SFW',
                );
            }

            $results[] = $result_entry;

            if ( $this->test && $_origin === 'sfw_test' ) {
                $this->test_status = $test_status;
            }
        }

        return $results;
    }

    /**
     * Add entry to SFW log.
     * Writes to database.
     *
     * @param string $ip
     * @param $status
     * @param string $network
     * @param string $source
     */
    public function updateLog($ip, $status, $network = 'NULL', $source = 'NULL')
    {
        $id = md5($ip . $this->module_name);
        $time = time();

        $this->db->prepareAndExecute(
            "INSERT INTO " . $this->db__table__logs . "
            SET
                id = '$id',
                ip = '$ip',
                status = '$status',
                all_entries = 1,
                blocked_entries = " . (strpos($status, 'DENY') !== false ? 1 : 0) . ",
                entries_timestamp = '" . $time . "',
                ua_name = %s,
                source = $source,
                network = %s,
                first_url = %s,
                last_url = %s
            ON DUPLICATE KEY
            UPDATE
                status = '$status',
                source = $source,
                all_entries = all_entries + 1,
                blocked_entries = blocked_entries" . (strpos($status, 'DENY') !== false ? ' + 1' : '') . ",
                entries_timestamp = '" . $time . "',
                ua_name = %s,
                network = %s,
                last_url = %s",
            array(
                Server::get('HTTP_USER_AGENT'),
                $network,
                substr(Server::get('HTTP_HOST') . Server::get('REQUEST_URI'), 0, 100),
                substr(Server::get('HTTP_HOST') . Server::get('REQUEST_URI'), 0, 100),

                Server::get('HTTP_USER_AGENT'),
                $network,
                substr(Server::get('HTTP_HOST') . Server::get('REQUEST_URI'), 0, 100),
            )
        );
    }

    public function actionsForDenied($result)
    {
        // Additional actions for the denied requests here
    }

    public function actionsForPassed($result)
    {
        // Additional actions for the passed requests here

        /*if ($this->data__cookies_type === 'native' && ! headers_sent()) {
            $status     = $result['status'] === 'PASS_SFW__BY_WHITELIST' ? '1' : '0';
            $cookie_val = md5($result['ip'] . $this->api_key) . $status;
            Cookie::setNativeCookie(
                'ct_sfw_pass_key',
                $cookie_val,
                time() + 86400 * 30,
                '/'
            );
        }*/
    }

    /**
     * Shows DIE page.
     * Stops script executing.
     *
     * @param array $result
     */
    public function diePage($result)
    {
        $fw_stats = Firewall::getFwStats();

        /** @var \Cleantalk\Common\RemoteCalls\Remotecalls $remote_calls_class */
        $remote_calls_class = Mloader::get('RemoteCalls');

        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler */
        $storage_handler = Mloader::get('StorageHandler');

        // File exists?
        if ( file_exists(__DIR__ . "/die_page_sfw.html") ) {
            $this->sfw_die_page = file_get_contents(__DIR__ . "/die_page_sfw.html");

            $net_count = $fw_stats->entries;

            $status = $result['status'] === 'PASS_SFW__BY_WHITELIST' ? '1' : '0';
            $cookie_val = md5($result['ip'] . $this->api_key) . $status;

            $block_message = sprintf(
                'SpamFireWall is checking your browser and IP %s for spam bots',
                '<a href="' . $result['ip'] . '" target="_blank">' . $result['ip'] . '</a>'
            );

            $request_uri = Server::get('REQUEST_URI');
            if ( $this->test ) {
                // Remove "sfw_test_ip" get parameter from the uri
                $request_uri = preg_replace('%sfw_test_ip=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}&?%', '', $request_uri);
            }

            // @ToDo not implemented yet
            // Custom Logo
            //$custom_logo_img = '';

            // Translation
            $replaces = array(
                '{SFW_DIE_NOTICE_IP}' => $block_message,
                '{SFW_DIE_MAKE_SURE_JS_ENABLED}' => 'To continue working with the web site, please make sure that you have enabled JavaScript.',
                '{SFW_DIE_CLICK_TO_PASS}' => 'Please click the link below to pass the protection,',
                '{SFW_DIE_YOU_WILL_BE_REDIRECTED}' => sprintf(
                    'Or you will be automatically redirected to the requested page after %d seconds.',
                    3
                ),
                '{CLEANTALK_TITLE}' => ($this->test ? 'This is the testing page for SpamFireWall' : ''),
                '{REMOTE_ADDRESS}' => $result['ip'],
                '{SERVICE_ID}' => $net_count,
                '{HOST}' => $remote_calls_class::getSiteUrl(),
                '{GENERATED}' => '<p>The page was generated at&nbsp;' . date('D, d M Y H:i:s') . '</p>',
                '{REQUEST_URI}' => $request_uri,

                // Cookie
                '{COOKIE_PREFIX}' => '',
                '{COOKIE_DOMAIN}' => '',
                '{COOKIE_SFW}' => $cookie_val,
                '{COOKIE_ANTICRAWLER}' => hash('sha256', $this->api_key . ''),

                // Test
                '{TEST_TITLE}' => '',
                '{REAL_IP__HEADER}' => '',
                '{TEST_IP__HEADER}' => '',
                '{TEST_IP}' => '',
                '{REAL_IP}' => '',
                '{SCRIPT_URL}' => $storage_handler::getJsLocation(),

                // Message about IP status
                '{MESSAGE_IP_STATUS}' => '',

                // Custom Logo
                '{CUSTOM_LOGO}' => ''
            );

            /**
             * Message about IP status
             */
            if ( $this->test ) {
                $message_ip_status = 'IP in the common blacklist';
                $message_ip_status_color = 'red';

                if ( $this->test_status === 1 ) {
                    $message_ip_status = 'IP in the whitelist';
                    $message_ip_status_color = 'green';
                }

                $replaces['{MESSAGE_IP_STATUS}'] = "<h3 style='color:$message_ip_status_color;'>$message_ip_status</h3>";
            }

            // Test
            if ( $this->test ) {
                $replaces['{TEST_TITLE}'] = 'This is the testing page for SpamFireWall';
                $replaces['{REAL_IP__HEADER}'] = 'Real IP:';
                $replaces['{TEST_IP__HEADER}'] = 'Test IP:';
                $replaces['{TEST_IP}'] = $this->test_ip;
                $replaces['{REAL_IP}'] = $this->real_ip;
            }

            // Debug
            if ( $this->debug ) {
                $debug = '<h1>Headers</h1>'
                    . var_export(Helper::httpGetHeaders(), true)
                    . '<h1>REMOTE_ADDR</h1>'
                    . Server::get('REMOTE_ADDR')
                    . '<h1>SERVER_ADDR</h1>'
                    . Server::get('REMOTE_ADDR')
                    . '<h1>IP_ARRAY</h1>'
                    . var_export($this->ip_array, true)
                    . '<h1>ADDITIONAL</h1>'
                    . var_export($this->debug_data, true);
            }
            $replaces['{DEBUG}'] = isset($debug) ? $debug : '';

            foreach ( $replaces as $place_holder => $replace ) {
                $replace = is_null($replace) ? '' : $replace;
                $this->sfw_die_page = str_replace($place_holder, $replace, $this->sfw_die_page);
            }
        }

        $this->printDiePage($result);
    }

    public function printDiePage($result)
    {
        parent::diePage($result);

        http_response_code(403);

        $localize_js = array(
            'sfw__random_get' => '1',
        );

        $localize_js_public = array();


        $replaces = array(
            '{JQUERY_SCRIPT_URL}' => '',
            '{LOCALIZE_SCRIPT}' => 'var ctPublicFunctions = ' . json_encode($localize_js) . ';' .
                'var ctPublic = ' . json_encode($localize_js_public) . ';',
        );

        foreach ( $replaces as $place_holder => $replace ) {
            $replace = is_null($replace) ? '' : $replace;
            $this->sfw_die_page = str_replace($place_holder, $replace, $this->sfw_die_page);
        }

        // File exists?
        if ( file_exists(__DIR__ . "/die_page_sfw.html") ) {
            die($this->sfw_die_page);
        }

        die("IP BLACKLISTED. Blocked by SFW " . $result['ip']);
    }

    /**
     * Sends and wipe SFW log
     *
     * @param $db
     * @param $log_table
     * @param string $ct_key Access key
     * @param bool $_use_delete_command Determs whether use DELETE or TRUNCATE to delete the logs table data
     *
     * @return array|bool array('error' => STRING)
     */
    public static function sendLog($db, $log_table, $ct_key, $_use_delete_command)
    {
        //Getting logs
        $query = "SELECT * FROM $log_table ORDER BY entries_timestamp DESC LIMIT 0," . APBCT_SFW_SEND_LOGS_LIMIT . ";";
        $db->fetchAll($query);

        if ( count($db->result) ) {
            $logs = $db->result;

            //Compile logs
            $ids_to_delete = array();
            $data = array();
            foreach ( $logs as $_key => &$value ) {
                $ids_to_delete[] = $value['id'];

                // Converting statuses to API format
                $value['status'] = $value['status'] === 'DENY_ANTICRAWLER' ? 'BOT_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_ANTICRAWLER' ? 'BOT_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'DENY_ANTICRAWLER_UA' ? 'BOT_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_ANTICRAWLER_UA' ? 'BOT_PROTECTION' : $value['status'];

                $value['status'] = $value['status'] === 'DENY_ANTIFLOOD' ? 'FLOOD_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_ANTIFLOOD' ? 'FLOOD_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'DENY_ANTIFLOOD_UA' ? 'FLOOD_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_ANTIFLOOD_UA' ? 'FLOOD_PROTECTION' : $value['status'];

                $value['status'] = $value['status'] === 'PASS_SFW__BY_COOKIE' ? 'DB_MATCH' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_SFW' ? 'DB_MATCH' : $value['status'];
                $value['status'] = $value['status'] === 'DENY_SFW' ? 'DB_MATCH' : $value['status'];

                $value['status'] = $value['source'] ? 'PERSONAL_LIST_MATCH' : $value['status'];

                $additional = array();
                if ( $value['network'] ) {
                    $additional['nd'] = $value['network'];
                }
                if ( $value['first_url'] ) {
                    $additional['fu'] = $value['first_url'];
                }
                if ( $value['last_url'] ) {
                    $additional['lu'] = $value['last_url'];
                }
                $additional = $additional ?: 'EMPTY_ASSOCIATIVE_ARRAY';

                $data[] = array(
                    trim($value['ip']),
                    // IP
                    $value['blocked_entries'],
                    // Count showing of block pages
                    $value['all_entries'] - $value['blocked_entries'],
                    // Count passed requests after block pages
                    $value['entries_timestamp'],
                    // Last timestamp
                    $value['status'],
                    // Status
                    $value['ua_name'],
                    // User-Agent name
                    $value['ua_id'],
                    // User-Agent ID
                    $additional
                    // Network, first URL, last URL
                );
            }
            unset($value);

            /** @var \Cleantalk\Common\Api\Api $api_class */
            $api_class = Mloader::get('Api');

            //Sending the request
            $result = $api_class::methodSfwLogs($ct_key, $data);
            //Checking answer and deleting all lines from the table
            if ( empty($result['error']) ) {
                if ( $result['rows'] == count($data) ) {
                    $db->execute("BEGIN;");
                    $db->execute("DELETE FROM $log_table WHERE id IN ( '" . implode('\',\'', $ids_to_delete) . "' );");
                    $db->execute("COMMIT;");

                    return $result;
                }

                return array('error' => 'SENT_AND_RECEIVED_LOGS_COUNT_DOESNT_MACH');
            } else {
                return $result;
            }
        } else {
            return array('rows' => 0);
        }
    }

    public static function directUpdateGetBlackLists($api_key)
    {
        /** @var \Cleantalk\Common\Api\Api $api_class */
        $api_class = Mloader::get('Api');

        // Getting remote file name
        $result = $api_class::methodGet2sBlacklistsDb($api_key, null, '3_1');

        if ( empty($result['error']) ) {
            return array(
                'blacklist' => isset($result['data']) ? $result['data'] : null,
                'useragents' => isset($result['data_user_agents']) ? $result['data_user_agents'] : null,
                'bl_count' => isset($result['networks_count']) ? $result['networks_count'] : null,
                'ua_count' => isset($result['ua_count']) ? $result['ua_count'] : null,
            );
        }

        return $result;
    }

    public static function directUpdate($db, $db__table__data, $blacklists)
    {
        if ( !is_array($blacklists) ) {
            return array('error' => 'BlackLists is not an array.');
        }
        for ( $count_result = 0; current($blacklists) !== false; ) {
            $query = "INSERT INTO " . $db__table__data . " (network, mask, status) VALUES ";

            for (
                $i = 0, $values = array();
                APBCT_WRITE_LIMIT !== $i && current($blacklists) !== false;
                $i++, $count_result++, next($blacklists)
            ) {
                $entry = current($blacklists);

                if ( empty($entry) ) {
                    continue;
                }

                // Cast result to int
                $ip = preg_replace('/[^\d]*/', '', $entry[0]);
                $mask = preg_replace('/[^\d]*/', '', $entry[1]);
                $private = isset($entry[2]) ? $entry[2] : 0;

                $values[] = '(' . $ip . ',' . $mask . ',' . $private . ')';
            }

            if ( !empty($values) ) {
                $query .= implode(',', $values) . ';';
                $result = $db->execute($query);
                if ( $result === false ) {
                    return array('error' => $db->getLastError());
                }
            }
        }

        return $count_result;
    }

    /**
     * Updates SFW local base
     *
     * @param $db
     * @param $db__table__data
     * @param null|string $file_url File URL with SFW data.
     *
     * @return array|int array('error' => STRING)
     */
    public static function updateWriteToDb($db, $db__table__data, $file_url = null)
    {
        $file_content = file_get_contents($file_url);

        if ( function_exists('gzdecode') ) {
            $unzipped_content = @gzdecode($file_content);

            if ( $unzipped_content !== false ) {
                /** @var \Cleantalk\Common\Helper\Helper $helper_class */
                $helper_class = Mloader::get('Helper');
                $data = $helper_class::bufferParseCsv($unzipped_content);

                if ( empty($data['errors']) ) {
                    reset($data);

                    for ( $count_result = 0; current($data) !== false; ) {
                        $query = "INSERT INTO " . $db__table__data . " (network, mask, status, source) VALUES ";

                        for (
                            $i = 0, $values = array();
                            APBCT_WRITE_LIMIT !== $i && current($data) !== false;
                            $i++, $count_result++, next($data)
                        ) {
                            $entry = current($data);

                            if ( empty($entry) || empty($entry[0]) || empty($entry[1]) ) {
                                continue;
                            }

                            // Cast result to int
                            $ip = preg_replace('/[^\d]*/', '', $entry[0]);
                            $mask = preg_replace('/[^\d]*/', '', $entry[1]);
                            $status = isset($entry[2]) ? $entry[2] : 0;
                            $source = isset($entry[3]) ? (int)$entry[3] : 'NULL';

                            $values[] = "($ip, $mask, $status, $source)";
                        }

                        if ( !empty($values) ) {
                            $query .= implode(',', $values) . ';';
                            if ( !$db->execute($query) ) {
                                return array(
                                    'error' => 'WRITE ERROR: FAILED TO INSERT DATA: ' . $db__table__data
                                        . ' DB Error: ' . $db->getLastError()
                                );
                            }
                            if ( file_exists($file_url) ) {
                                unlink($file_url);
                            }
                        }
                    }

                    return $count_result;
                } else {
                    return $data;
                }
            } else {
                return array('error' => 'Can not unpack datafile');
            }
        } else {
            return array('error' => 'Function gzdecode not exists. Please update your PHP at least to version 5.4 ');
        }
    }

    /**
     * @param $db
     * @param $db__table__data
     * @param $exclusions
     *
     * @return int|string[]
     *
     * @since version
     */
    public static function updateWriteToDbExclusions($db, $db__table__data, $exclusions = array())
    {
        $fw_stats = Firewall::getFwStats();

        /** @var \Cleantalk\Common\Helper\Helper $helper_class */
        $helper_class = Mloader::get('Helper');

        $query = 'INSERT INTO `' . $db__table__data . '` (network, mask, status) VALUES ';

        //Exclusion for servers IP (SERVER_ADDR)
        if ( Server::get('HTTP_HOST') ) {
            // Do not add exceptions for local hosts
            if ( !in_array(Server::getDomain(), array('lc', 'loc', 'lh')) ) {
                $exclusions[] = $helper_class::dnsResolve(Server::get('HTTP_HOST'));
                $exclusions[] = '127.0.0.1';
                // And delete all 127.0.0.1 entries for local hosts
            } else {
                // @ToDo Implement this after moving queries in the separate model class
            }
        }

        foreach ( $exclusions as $exclusion ) {
            if ( $helper_class::ipValidate($exclusion) && sprintf('%u', ip2long($exclusion)) ) {
                $query .= '('
                    . sprintf('%u', ip2long($exclusion))
                    . ', '
                    . sprintf('%u', bindec(str_repeat('1', 32)))
                    . ', 1),';
            }
        }

        if ( $exclusions ) {
            $sql_result = $db->execute(substr($query, 0, -1) . ';');

            return $sql_result === false
                ? array('error' => 'COULD_NOT_WRITE_TO_DB 4: ' . $db->getLastError())
                : count($exclusions);
        }

        return 0;
    }

    /**
     * Creating a temporary updating table
     *
     * @param \Cleantalk\Common\Db\Db $db database handler
     * @param array|string $table_names Array with table names to create
     *
     * @return bool|array
     */
    public static function createTempTables($db, $table_names)
    {
        // Cast it to array for simple input
        $table_names = (array)$table_names;

        foreach ( $table_names as $table_name ) {
            $table_name__temp = $table_name . '_temp';

            if ( !$db->execute('CREATE TABLE IF NOT EXISTS `' . $table_name__temp . '` LIKE `' . $table_name . '`;') ) {
                return array(
                    'error' => 'CREATE TEMP TABLES: COULD NOT CREATE ' . $table_name__temp
                        . ' DB Error: ' . $db->getLastError()
                );
            }

            if ( !$db->execute('TRUNCATE TABLE `' . $table_name__temp . '`;') ) {
                return array(
                    'error' => 'CREATE TEMP TABLES: COULD NOT TRUNCATE' . $table_name__temp
                        . ' DB Error: ' . $db->getLastError()
                );
            }
        }

        return true;
    }

    /**
     * Delete tables with given names if they exists
     *
     * @param \Cleantalk\Common\Db\Db $db
     * @param array|string $table_names Array with table names to delete
     *
     * @return bool|array
     */
    public static function dataTablesDelete($db, $table_names)
    {
        // Cast it to array for simple input
        $table_names = (array)$table_names;

        foreach ( $table_names as $table_name ) {
            if ( $db->isTableExists($table_name) && !$db->execute('DROP TABLE ' . $table_name . ';') ) {
                return array(
                    'error' => 'DELETE TABLE: FAILED TO DROP: ' . $table_name
                        . ' DB Error: ' . $db->getLastError()
                );
            }
        }

        return true;
    }

    /**
     * Renaming a temporary updating table into production table name
     *
     * @param \Cleantalk\Common\Db\Db $db database handler
     * @param array|string $table_names Array with table names to rename
     *
     * @return bool|array
     */
    public static function renameDataTablesFromTempToMain($db, $table_names)
    {
        // Cast it to array for simple input
        $table_names = (array)$table_names;

        foreach ( $table_names as $table_name ) {
            $table_name__temp = $table_name . '_temp';

            if ( !$db->isTableExists($table_name__temp) ) {
                return array('error' => 'RENAME TABLE: TEMPORARY TABLE IS NOT EXISTS: ' . $table_name__temp);
            }

            if ( $db->isTableExists($table_name) ) {
                //return array('error' => 'RENAME TABLE: MAIN TABLE IS STILL EXISTS: ' . $table_name);
            }

            $alter_res = $db->execute('ALTER TABLE `' . $table_name__temp . '` RENAME `' . $table_name . '`;');
            if ( ! $alter_res ) {
                return array(
                    'error' => 'RENAME TABLE: FAILED TO RENAME: ' . $table_name
                        . ' DB Error: ' . $db->getLastError()
                );
            }
        }

        return true;
    }
}
