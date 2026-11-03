<?php

namespace Cleantalk\Tests\Custom\Helper;

use Cleantalk\Custom\Helper\Helper;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class HelperTest extends TestCase
{
    private $server;
    private $get;
    private $post;
    private $errorLog;
    private $previousErrorLog;

    protected function setUp(): void
    {
        $this->server = $_SERVER;
        $this->get = $_GET;
        $this->post = $_POST;
        $_GET = [];
        $_POST = [];
        unset($_SERVER['HTTP_HOST'], $_SERVER['HTTPS'], $_SERVER['SCRIPT_URL']);
        $this->errorLog = tempnam(sys_get_temp_dir(), 'cleantalk-helper-');
        $this->assertNotFalse($this->errorLog);
        $this->previousErrorLog = ini_set('error_log', $this->errorLog);
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->server;
        $_GET = $this->get;
        $_POST = $this->post;
        ini_set('error_log', $this->previousErrorLog);
        unlink($this->errorLog);
    }

    /**
     * @dataProvider scalarValueProvider
     */
    public function testObfuscateScalarValues($value, $expected)
    {
        $this->assertSame($expected, Helper::obfuscate_param($value));
    }

    public function scalarValueProvider()
    {
        return [
            'null' => [null, null],
            'empty string' => ['', ''],
            'string' => ['secret', '******'],
            'string zero' => ['0', '*'],
            'integer zero' => [0, '*'],
            'float zero' => [0.0, '*'],
            'integer' => [123, '***'],
            'negative integer' => [-12, '***'],
            'float' => [1.5, '***'],
            'true' => [true, '*'],
            'false' => [false, ''],
        ];
    }

    public function testObfuscateDefaultValueRemainsNull()
    {
        $this->assertNull(Helper::obfuscate_param());
    }

    /**
     * @dataProvider nonScalarValueProvider
     */
    public function testObfuscateRejectsNonScalarValues($value)
    {
        $this->assertNull(Helper::obfuscate_param($value));
        $log = file_get_contents($this->errorLog);
        $this->assertStringContainsString('Only scalar values or null can be masked.', $log);
        $this->assertStringNotContainsString('secret', $log);
    }

    public function nonScalarValueProvider()
    {
        return [
            'empty array' => [[]],
            'nonempty array' => [['secret']],
            'object' => [new \stdClass()],
        ];
    }

    public function testObfuscateRejectsResources()
    {
        $resource = fopen('php://memory', 'r+');
        $this->assertIsResource($resource);
        try {
            $this->assertNull(Helper::obfuscate_param($resource));
            $this->assertStringContainsString(
                'Only scalar values or null can be masked.',
                file_get_contents($this->errorLog)
            );
        } finally {
            fclose($resource);
        }
    }

    /**
     * @dataProvider siteUrlProvider
     */
    public function testSiteUrlPreservesSchemeHostAndScriptPath($server, $expected)
    {
        foreach ($server as $name => $value) {
            $_SERVER[$name] = $value;
        }

        $this->assertSame($expected, $this->getSiteUrl());
    }

    public function siteUrlProvider()
    {
        return [
            'HTTP host' => [
                ['HTTP_HOST' => 'example.com'],
                'http://example.com',
            ],
            'HTTPS and script path' => [
                ['HTTP_HOST' => 'example.com', 'HTTPS' => 'on', 'SCRIPT_URL' => '/index.php'],
                'https://example.com/index.php',
            ],
            'HTTPS disabled and port' => [
                ['HTTP_HOST' => 'example.com:8080', 'HTTPS' => 'off', 'SCRIPT_URL' => '/joomla/'],
                'http://example.com:8080/joomla/',
            ],
        ];
    }

    /**
     * @dataProvider missingHostProvider
     */
    public function testSiteUrlRejectsMissingHost($server)
    {
        foreach ($server as $name => $value) {
            $_SERVER[$name] = $value;
        }
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unable to build the site URL: HTTP_HOST is not available.');

        $this->getSiteUrl();
    }

    public function missingHostProvider()
    {
        return [
            'absent' => [[]],
            'empty' => [['HTTP_HOST' => '']],
            'null' => [['HTTP_HOST' => null]],
        ];
    }

    /**
     * @dataProvider missingHostProvider
     */
    public function testRemoteCallReportsMissingHostWithoutHttpRequests($server)
    {
        foreach ($server as $name => $value) {
            $_SERVER[$name] = $value;
        }

        $this->assertSame(
            ['error' => 'Unable to build the site URL: HTTP_HOST is not available.'],
            HelperHttpStub::http__request__rc_to_host('test_action', [])
        );
        $this->assertSame([], HelperHttpStub::$requests);
        $this->assertStringContainsString('Remote call skipped:', file_get_contents($this->errorLog));
    }

    public function testRemoteCallPreservesRequestsWithValidHost()
    {
        $_SERVER['HTTP_HOST'] = 'example.com';

        $this->assertTrue(HelperHttpStub::http__request__rc_to_host('test_action', ['key' => 'value']));
        $this->assertSame([
            [
                'http://example.com',
                ['spbc_remote_call_action' => 'test_action', 'plugin_name' => 'apbct', 'key' => 'value', 'test' => 'test'],
                ['get', 'dont_split_to_array'],
            ],
            [
                'http://example.com',
                ['spbc_remote_call_action' => 'test_action', 'plugin_name' => 'apbct', 'key' => 'value'],
                ['get'],
            ],
        ], HelperHttpStub::$requests);
        $this->assertSame('', file_get_contents($this->errorLog));
    }

    /**
     * @dataProvider incompleteFirewallStatsProvider
     */
    public function testSetFwStatsRejectsMissingKeysBeforeAccessingJoomla($stats)
    {
        $this->assertNull(Helper::setFwStats($stats));
        $this->assertStringContainsString(
            'Firewall statistics must include firewall_updating_id and firewall_updating_last_start.',
            file_get_contents($this->errorLog)
        );
    }

    public function incompleteFirewallStatsProvider()
    {
        return [
            'both absent' => [[]],
            'start absent' => [['firewall_updating_id' => null]],
            'ID absent' => [['firewall_updating_last_start' => 0]],
        ];
    }

    public function testSetFwStatsAcceptsPresentNullValues()
    {
        $this->setUpDatabase();

        Helper::setFwStats([
            'firewall_updating_id' => null,
            'firewall_updating_last_start' => null,
        ]);
        $this->assertSame('', file_get_contents($this->errorLog));
    }

    /**
     * @dataProvider firewallOperationProvider
     */
    public function testFirewallOperationSkipsUnavailableTable($method)
    {
        $this->setUpDatabase((object) ['extension_id' => 1]);
        class_alias(HelperTableStub::class, 'JTable');

        $this->assertNull(Helper::$method([
            'firewall_updating_id' => 'update-id',
            'firewall_updating_last_start' => 123,
        ]));
        $this->assertStringContainsString(
            'Unable to create the Joomla extension table instance.',
            file_get_contents($this->errorLog)
        );
        $this->assertSame(1, HelperTableStub::$calls);
    }

    public function firewallOperationProvider()
    {
        return [
            'saving statistics' => ['setFwStats'],
            'finishing an update' => ['SfwUpdate_DoFinisnAction'],
        ];
    }

    /**
     * @dataProvider firewallOperationProvider
     */
    public function testFirewallOperationPreservesExistingSettings($method)
    {
        $this->setUpDatabase((object) ['extension_id' => 1]);
        class_alias(HelperTableStub::class, 'JTable');
        class_alias(HelperRegistryStub::class, 'JRegistry');
        HelperTableStub::$instance = new HelperStoredTableStub();

        Helper::$method([
            'firewall_updating_id' => null,
            'firewall_updating_last_start' => null,
        ]);

        $saved = json_decode(HelperTableStub::$instance->params, true);
        $this->assertSame('kept', $saved['existing']);
        if ($method === 'setFwStats') {
            $this->assertArrayHasKey('firewall_updating_id', $saved);
            $this->assertNull($saved['firewall_updating_id']);
            $this->assertArrayHasKey('firewall_updating_last_start', $saved);
            $this->assertNull($saved['firewall_updating_last_start']);
        } else {
            $this->assertIsInt($saved['sfw_last_check']);
        }
        $this->assertSame(1, HelperTableStub::$instance->stores);
        $this->assertSame('', file_get_contents($this->errorLog));
    }

    private function setUpDatabase($plugin = null)
    {
        class_alias(HelperFactoryStub::class, 'JFactory');

        $query = $this->getMockBuilder(\stdClass::class)
            ->addMethods(['select', 'from', 'where'])
            ->getMock();
        $query->method('select')->willReturnSelf();
        $query->method('from')->willReturnSelf();
        $query->method('where')->willReturnSelf();

        $db = $this->getMockBuilder(\stdClass::class)
            ->addMethods(['getQuery', 'quoteName', 'quote', 'setQuery', 'execute', 'loadObject'])
            ->getMock();
        $db->method('getQuery')->with(true)->willReturn($query);
        $db->method('quoteName')->willReturnArgument(0);
        $db->method('quote')->willReturnArgument(0);
        $db->expects($this->once())->method('setQuery')->with($query);
        $db->expects($this->once())->method('execute');
        $db->method('loadObject')->willReturn($plugin);
        HelperFactoryStub::$database = $db;
    }

    public function testGetFieldsPreservesFormDataAndSkipsSensitiveAndExcludedFields()
    {
        $result = Helper::get_fields_any([
            'email' => 'sender@example.com',
            'first_name' => 'Alice',
            'last_name' => 'Smith',
            'subject' => 'Hello',
            'message' => 'Hello+world',
            'password' => 'secret',
            'excluded' => 'hidden',
            'nested' => ['message' => 'Nested+text'],
        ], 'excluded');

        $this->assertSame('sender@example.com', $result['email']);
        $this->assertSame('Alice Smith ', $result['nickname']);
        $this->assertSame('Hello', $result['subject']);
        $this->assertTrue($result['contact']);
        $this->assertSame([
            'message' => 'Hello world',
            'nested_message' => 'Nested text',
        ], $result['message']);
    }

    public function testGetFieldsPreservesCommaSeparatedAndBracketedExclusions()
    {
        $result = Helper::get_fields_any([
            'submitted_name' => 'hidden name',
            'excluded' => 'hidden text',
            'message' => 'visible text',
        ], 'submitted[name],excluded');

        $this->assertSame(['message' => 'visible text'], $result['message']);
    }

    private function getSiteUrl()
    {
        $reflection = new ReflectionClass(Helper::class);
        $method = $reflection->getMethod('getSiteUrl');
        $method->setAccessible(true);
        return $method->invoke(null);
    }
}

class HelperFactoryStub
{
    public static $database;

    public static function getDBO()
    {
        return self::$database;
    }
}

class HelperTableStub
{
    public static $calls = 0;
    public static $instance = false;

    public static function getInstance($type)
    {
        self::$calls++;
        return self::$instance;
    }
}

class HelperStoredTableStub
{
    public $params = '{"existing":"kept"}';
    public $stores = 0;

    public function load($id)
    {
        return true;
    }

    public function store()
    {
        $this->stores++;
        return true;
    }
}

class HelperRegistryStub
{
    private $data;

    public function __construct($params)
    {
        $this->data = json_decode($params, true);
    }

    public function set($name, $value)
    {
        $this->data[$name] = $value;
    }

    public function toString()
    {
        return json_encode($this->data);
    }
}

class HelperHttpStub extends Helper
{
    public static $requests = [];

    public static function httpRequest($url, $data = [], $presets = [], $opts = [])
    {
        self::$requests[] = [$url, $data, $presets];
        return 'OK';
    }
}
