<?php

namespace {
    if (!function_exists('jimport')) {
        function jimport($path)
        {
        }
    }
}

namespace Cleantalk\Tests\Plugin {
    use Cleantalk\Common\Helper\Helper;
    use PHPUnit\Framework\TestCase;
    use ReflectionClass;
    use ReflectionMethod;

    /**
     * @runTestsInSeparateProcesses
     * @preserveGlobalState disabled
     */
    class RequestErrorHandlingTest extends TestCase
    {
        private $plugin;
        private $errorLog;
        private $previousErrorLog;

        protected function setUp(): void
        {
            foreach ([
                'JPlugin' => PluginStub::class,
                'JFactory' => FactoryStub::class,
                'JRegistry' => RegistryStub::class,
                'JTable' => TableStub::class,
                'JSession' => SessionStub::class,
                'JFilterInput' => FilterStub::class,
                'Cleantalk\Common\Api\Api' => ApiStub::class,
                'Cleantalk\Custom\Helper\Helper' => IpHelperStub::class,
                'Cleantalk\Common\Antispam\Cleantalk' => ClientStub::class,
            ] as $alias => $class) {
                class_alias($class, $alias);
            }
            if (!defined('_JEXEC')) {
                define('_JEXEC', 1);
            }
            require_once dirname(__DIR__, 3) . '/cleantalkantispam.php';
            $reflection = new ReflectionClass(\plgSystemCleantalkantispam::class);
            $this->plugin = $reflection->newInstanceWithoutConstructor();
            $property = $reflection->getProperty('_id');
            $property->setAccessible(true);
            $property->setValue($this->plugin, 1);
            $this->plugin->cms_version = '6.2.0';
            $this->plugin->params = new RegistryStub([
                'apikey' => 'test-key',
                'ct_key_is_ok' => 1,
                'ct_set_cookies' => 0,
            ]);
            FactoryStub::$application = new ApplicationStub();
            TableStub::$instance = new TableStub();
            $_SERVER['REQUEST_URI'] = '/contact';
            $_SERVER['HTTP_HOST'] = 'example.com';
            unset($_SERVER['HTTP_REFERER'], $_SERVER['HTTP_USER_AGENT']);
            $_COOKIE = [];
            $_POST = [];
            $this->errorLog = tempnam(sys_get_temp_dir(), 'cleantalk-plugin-');
            $this->assertNotFalse($this->errorLog);
            $this->previousErrorLog = ini_set('error_log', $this->errorLog);
        }

        protected function tearDown(): void
        {
            ini_set('error_log', $this->previousErrorLog);
            unlink($this->errorLog);
        }

        /**
         * @dataProvider invalidUtf8Provider
         */
        public function testInvalidUtf8PreservesCloudDecisionAndRemainingMetadata($parameter, $cookie, $field, $allow)
        {
            ClientStub::$allow = $allow;
            $this->plugin->params->set('js_keys', ['valid-key' => time()]);
            $_COOKIE['ct_checkjs'] = 'valid-key';
            if ($parameter) {
                $this->plugin->params->set('custom_option', "\xB1");
            } else {
                $_COOKIE[$cookie] = "\xB1";
            }

            $response = $this->invoke('ctSendRequest', ['check_message', [
                'sender_email' => 'sender@example.com', 'message' => 'Hello',
            ]]);

            $this->assertSame($allow, $response['allow']);
            $this->assertSame('cloud-id', $response['id']);
            $this->assertSame(1, count(ClientStub::$requests));
            $request = ClientStub::$requests[0];
            $this->assertSame('sender@example.com', $request->sender_email);
            $this->assertSame('Hello', $request->message);
            $this->assertSame(1, $request->js_on);
            $metadata = json_decode($request->sender_info, true);
            $this->assertSame(JSON_ERROR_NONE, json_last_error());
            $this->assertSame('en', $metadata['cms_lang']);
            if ($parameter) {
                $options = json_decode($metadata['ct_options'], true);
                $this->assertSame("\xEF\xBF\xBD", $options['custom_option']);
                $this->assertSame('test-key', $options['apikey']);
            } else {
                $this->assertSame("\xEF\xBF\xBD", $metadata[$field]);
            }
            $saved = json_decode(TableStub::$instance->savedParams, true);
            $this->assertSame(1, $saved['connection_reports']['success']);
            $this->assertSame('', $this->log());
            $this->assertFalse($this->invoke('ctSendRequest', ['check_message', []]));
        }

        public function invalidUtf8Provider()
        {
            $sources = [
                'options' => [true, null, null],
                'timestamp cookie' => [false, 'ct_ps_timestamp', 'page_set_timestamp'],
                'timezone cookie' => [false, 'ct_timezone', 'js_timezone'],
                'key press cookie' => [false, 'ct_fkp_timestamp', 'key_press_timestamp'],
                'pointer cookie' => [false, 'ct_pointer_data', 'mouse_cursor_positions'],
                'previous referrer cookie' => [false, 'apbct_prev_referer', 'REFFERRER_PREVIOUS'],
            ];
            foreach ($sources as $name => $source) {
                foreach ([0, 1, '0', '1'] as $allow) {
                    yield $name . ' ' . var_export($allow, true) => array_merge($source, [$allow]);
                }
            }
        }

        /**
         * @dataProvider decisionProvider
         */
        public function testAjaxPreservesCloudDecisionWithInvalidUtf8Cookie($allow)
        {
            ClientStub::$allow = $allow;
            $_COOKIE['ct_pointer_data'] = "\xB1";
            FactoryStub::$requestData = ['action' => 'check_ajax'];

            $this->assertSame(
                ['allow' => (int) $allow, 'msg' => $allow == 0 ? 'Cloud decision' : ''],
                json_decode($this->plugin->onAjaxCleantalkantispam(), true)
            );
            $this->assertSame(1, count(ClientStub::$requests));
            $this->assertSame('', $this->log());
        }

        /**
         * @dataProvider encodingFailureProvider
         */
        public function testEncodingFailureUsesEmptyMetadataWithoutSkippingModeration($kind, $allow)
        {
            ClientStub::$allow = $allow;
            $this->plugin->params->set('js_keys', ['valid-key' => time()]);
            $_COOKIE['ct_checkjs'] = 'invalid-key';
            $value = null;
            if ($kind === 'resource') {
                $value = fopen('php://memory', 'r+');
                $this->assertIsResource($value);
            } elseif ($kind === 'recursion' || $kind === 'cookie-recursion') {
                $value = new \stdClass();
                $value->self = $value;
            } else {
                for ($depth = 0; $depth < 513; $depth++) {
                    $value = [$value];
                }
            }
            if ($kind === 'cookie-recursion') {
                $_COOKIE['ct_pointer_data'] = $value;
            } else {
                $this->plugin->params->set('custom_option', $value);
            }

            try {
                $response = $this->invoke('ctSendRequest', ['check_message', [
                    'sender_email' => 'sender@example.com', 'message' => 'Hello',
                ]]);
                $this->assertSame($allow, $response['allow']);
                $this->assertSame('cloud-id', $response['id']);
                $this->assertSame(1, count(ClientStub::$requests));
                $request = ClientStub::$requests[0];
                $this->assertSame('{}', $request->sender_info);
                $this->assertSame('203.0.113.8', $request->sender_ip);
                $this->assertSame('sender@example.com', $request->sender_email);
                $this->assertSame('Hello', $request->message);
                $this->assertSame(0, $request->js_on);
                $this->assertStringContainsString(
                    'Sender metadata omitted: Unable to encode sender '
                    . ($kind === 'cookie-recursion' ? 'info:' : 'options:'),
                    $this->log()
                );
                $this->assertStringNotContainsString('test-key', $this->log());
                $this->assertStringNotContainsString('Moderation skipped:', $this->log());
            } finally {
                if (is_resource($value)) {
                    fclose($value);
                }
            }
        }

        public function encodingFailureProvider()
        {
            foreach (['resource', 'recursion', 'depth', 'cookie-recursion'] as $kind) {
                foreach ([0, 1, '0', '1'] as $allow) {
                    yield $kind . ' ' . var_export($allow, true) => [$kind, $allow];
                }
            }
        }

        /**
         * @dataProvider decisionProvider
         */
        public function testAjaxPreservesCloudDecisionWhenMetadataIsOmitted($allow)
        {
            ClientStub::$allow = $allow;
            $value = new \stdClass();
            $value->self = $value;
            $this->plugin->params->set('custom_option', $value);
            FactoryStub::$requestData = ['action' => 'check_ajax'];

            $this->assertSame(
                ['allow' => (int) $allow, 'msg' => $allow == 0 ? 'Cloud decision' : ''],
                json_decode($this->plugin->onAjaxCleantalkantispam(), true)
            );
            $this->assertSame(1, count(ClientStub::$requests));
            $this->assertSame('{}', ClientStub::$requests[0]->sender_info);
            $this->assertStringContainsString('Sender metadata omitted:', $this->log());
        }

        /**
         * @dataProvider decisionProvider
         */
        public function testNormalModerationPreservesDecisionAndSuccessReport($allow)
        {
            ClientStub::$allow = $allow;

            $response = $this->invoke('ctSendRequest', ['check_newuser', []]);

            $this->assertSame($allow, $response['allow']);
            $this->assertSame('cloud-id', $response['id']);
            $this->assertSame(1, ClientStub::$instances);
            $saved = json_decode(TableStub::$instance->savedParams, true);
            $this->assertSame(1, $saved['connection_reports']['success']);
            $this->assertSame('', $this->log());
        }

        public function decisionProvider()
        {
            return [[0], [1], ['0'], ['1']];
        }

        /**
         * @dataProvider decisionProvider
         */
        public function testSettingsFailureDoesNotOverrideCloudDecision($allow)
        {
            ClientStub::$allow = $allow;
            TableStub::$instance = false;

            $response = $this->invoke('ctSendRequest', ['check_newuser', []]);

            $this->assertSame($allow, $response['allow']);
            $this->assertSame('cloud-id', $response['id']);
            $this->assertSame(1, ClientStub::$instances);
            $this->assertStringContainsString('Unable to create the Joomla extension table instance.', $this->log());
            $this->assertStringNotContainsString('Moderation skipped:', $this->log());
        }

        public function testUnrelatedClientExceptionIsNotSuppressed()
        {
            ClientStub::$exception = new \RuntimeException('Client failed.');
            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessage('Client failed.');

            $this->invoke('ctSendRequest', ['check_message', []]);
        }

        /**
         * @dataProvider saveFailureProvider
         */
        public function testSavingSettingsReportsFailureWithoutFatal($failure, $message)
        {
            $table = TableStub::$instance;
            $this->configureSaveFailure($failure);

            $this->assertFalse($this->invoke('saveCTConfig', [['setting' => 'new']]));
            $this->assertStringContainsString($message, $this->log());
            $this->assertSame('{"existing":"kept"}', $table->savedParams);
            $this->assertSame($failure === 'store' ? 1 : 0, $table->stores);
        }

        /**
         * @dataProvider saveFailureProvider
         */
        public function testAjaxDoesNotReportDismissedNoticeAfterSaveFailure($failure, $message)
        {
            $this->configureSaveFailure($failure);
            FactoryStub::$requestData = ['action' => 'dismiss_notice', 'data' => ['notice_type' => 'trial']];

            $this->assertSame(
                ['error' => 'Unable to save the CleanTalk notice settings.'],
                $this->plugin->onAjaxCleantalkantispam()
            );
            $this->assertStringContainsString($message, $this->log());
        }

        public function saveFailureProvider()
        {
            return [
                'missing table' => ['table', 'Unable to create the Joomla extension table instance.'],
                'failed load' => ['load', 'Unable to load the Joomla extension settings.'],
                'failed store' => ['store', 'Unable to store the Joomla extension settings.'],
            ];
        }

        public function testSavingSettingsPreservesExistingValues()
        {
            $this->assertTrue($this->invoke('saveCTConfig', [['setting' => 'new']]));
            $this->assertSame(['existing' => 'kept', 'setting' => 'new'], json_decode(TableStub::$instance->savedParams, true));
            $this->assertSame(1, TableStub::$instance->stores);
            $this->assertSame('', $this->log());
        }

        public function testPaidStatusWithoutUserTokenPreservesSavedToken()
        {
            $this->plugin->params->set('apikey', 'testkey');
            $this->plugin->params->set('user_token', 'saved-user-token');
            TableStub::$instance->params = json_encode([
                'apikey' => 'testkey',
                'user_token' => 'saved-user-token',
            ]);
            ApiStub::$noticeResponse = ['valid' => 1, 'service_id' => 123];

            $this->invoke('checkIsPaid', ['testkey', true]);

            $saved = json_decode(TableStub::$instance->savedParams, true);
            $this->assertSame('saved-user-token', $saved['user_token']);
            $this->assertSame(1, $saved['ct_key_is_ok']);
            $this->assertSame(['notice_paid_till'], ApiStub::$calls);
            $this->assertSame('', $this->log());
        }

        /**
         * @dataProvider automaticKeyResponseProvider
         */
        public function testAutomaticKeyPreservesResponseWithoutPaidStatusRequest($response)
        {
            ApiStub::$keyResponse = $response;

            $this->assertSame(
                $response,
                $this->invoke('gettingKeyAutomatically', [ApiStub::class])
            );
            $this->assertSame(['get_api_key'], ApiStub::$calls);
            $this->assertSame('', $this->log());
        }

        public function automaticKeyResponseProvider()
        {
            return [
                'with token' => [['auth_key' => 'autokey', 'user_token' => 'auto-user-token']],
                'without token' => [['auth_key' => 'autokey']],
            ];
        }

        public function testEmptySettingsDoNotRequireTable()
        {
            TableStub::$instance = false;

            $this->assertTrue($this->invoke('saveCTConfig', [[]]));
            $this->assertSame('', $this->log());
        }

        public function testAjaxReportsSuccessfullySavedNotice()
        {
            FactoryStub::$requestData = ['action' => 'dismiss_notice', 'data' => ['notice_type' => 'trial']];

            $this->assertSame(
                ['success' => 'The notice dismissing was remembered'],
                $this->plugin->onAjaxCleantalkantispam()
            );
            $saved = json_decode(TableStub::$instance->savedParams, true);
            $this->assertIsInt($saved['cleantalk_trial_7_dismissed']);
            $this->assertSame('kept', $saved['existing']);
            $this->assertSame('', $this->log());
        }

        private function configureSaveFailure($failure)
        {
            if ($failure === 'table') {
                TableStub::$instance = false;
            } elseif ($failure === 'load') {
                TableStub::$instance->loaded = false;
            } else {
                TableStub::$instance->stored = false;
            }
        }

        private function invoke($method, $arguments)
        {
            $reflection = new ReflectionMethod($this->plugin, $method);
            $reflection->setAccessible(true);
            return $reflection->invokeArgs($this->plugin, $arguments);
        }

        private function log()
        {
            return file_get_contents($this->errorLog);
        }
    }

    class PluginStub
    {
    }

    class RegistryStub
    {
        private $data;

        public function __construct($data = [])
        {
            $this->data = is_string($data) ? json_decode($data, true) : $data;
        }

        public function get($key, $default = null)
        {
            return $this->data[$key] ?? $default;
        }

        public function set($key, $value)
        {
            $this->data[$key] = $value;
        }

        public function toArray()
        {
            return $this->data;
        }

        public function toString()
        {
            return json_encode($this->data);
        }
    }

    class FactoryStub
    {
        public static $application;
        public static $requestData = [];

        public static function getApplication()
        {
            return self::$application;
        }

        public static function getConfig()
        {
            return new RegistryStub(['mailfrom' => 'admin@example.com']);
        }

        public static function getUser()
        {
            return new class {
                public $id = 7;
                public $guest = true;

                public function authorise($permission)
                {
                    return false;
                }
            };
        }

        public static function getLanguage()
        {
            return new class {
                public function getTag()
                {
                    return 'en-GB';
                }
            };
        }
    }

    class ApplicationStub
    {
        public $input;

        public function __construct()
        {
            $this->input = new InputStub();
        }

        public function isClient($name)
        {
            return $name === 'site';
        }
    }

    class InputStub
    {
        public $json;

        public function __construct()
        {
            $this->json = $this;
        }

        public function get($name)
        {
            return $name === 'option' ? 'com_ajax' : null;
        }

        public function getArray()
        {
            return FactoryStub::$requestData;
        }
    }

    class TableStub
    {
        public static $instance;
        public $params = '{"existing":"kept"}';
        public $savedParams = '{"existing":"kept"}';
        public $loaded = true;
        public $stored = true;
        public $stores = 0;

        public static function getInstance($type)
        {
            return self::$instance;
        }

        public function load($id)
        {
            return $this->loaded;
        }

        public function store()
        {
            $this->stores++;
            if ($this->stored) {
                $this->savedParams = $this->params;
            }
            return $this->stored;
        }
    }

    class SessionStub
    {
        public static function checkToken($method)
        {
            return true;
        }
    }

    class FilterStub
    {
        public static function getInstance()
        {
            return new self();
        }

        public function clean($value)
        {
            return $value;
        }
    }

    class IpHelperStub extends Helper
    {
        public static function ipGet($ip_type_to_get = 'real', $v4_only = true, $headers = [])
        {
            return '203.0.113.8';
        }
    }

    class ApiStub
    {
        public static $keyResponse = [];
        public static $noticeResponse = [];
        public static $calls = [];

        public static function methodGetApiKey($product, $email, $host, $platform)
        {
            self::$calls[] = 'get_api_key';

            return self::$keyResponse;
        }

        public static function methodNoticePaidTill($api_key, $host)
        {
            self::$calls[] = 'notice_paid_till';

            return self::$noticeResponse;
        }
    }

    class ClientStub
    {
        public static $instances = 0;
        public static $requests = [];
        public static $allow = 1;
        public static $exception;
        public $server_change = false;
        public $server_url;
        public $work_url;
        public $server_ttl;
        public $server_changed;

        public function __construct()
        {
            self::$instances++;
        }

        public function isAllowMessage($request)
        {
            self::$requests[] = $request;
            if (self::$exception !== null) {
                throw self::$exception;
            }
            return (object) [
                'allow' => self::$allow, 'comment' => 'Cloud decision', 'errno' => 0,
                'errstr' => '', 'id' => 'cloud-id', 'stop_queue' => 0, 'stop_words' => null,
            ];
        }

        public function isAllowUser($request)
        {
            return $this->isAllowMessage($request);
        }
    }
}
