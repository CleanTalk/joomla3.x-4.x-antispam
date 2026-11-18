<?php

namespace Cleantalk\Tests\Custom\FindSpam\UsersChecker;

use Cleantalk\Common\Api\Api;
use Cleantalk\Common\StorageHandler\StorageHandler;
use Cleantalk\Custom\FindSpam\UsersChecker\Model\Model;
use Cleantalk\Custom\FindSpam\UsersChecker\UsersChecker;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class UsersCheckerTest extends TestCase
{
    private $checker;
    private $model;

    protected function setUp(): void
    {
        class_alias(UsersCheckerApiStub::class, 'Cleantalk\Custom\Api\Api');
        class_alias(UsersCheckerStorageStub::class, 'Cleantalk\Custom\StorageHandler\StorageHandler');
        class_alias(UsersCheckerTextStub::class, 'JText');

        $this->model = $this->getMockBuilder(Model::class)
            ->disableOriginalConstructor()
            ->getMock();

        $reflection = new ReflectionClass(UsersChecker::class);
        $this->checker = $reflection->newInstanceWithoutConstructor();
        foreach (['api_key' => 'test-key', 'model' => $this->model] as $name => $value) {
            $property = $reflection->getProperty($name);
            $property->setAccessible(true);
            $property->setValue($this->checker, $value);
        }
    }

    public function testMissingApiKeyStopsBeforeAccessingDependencies()
    {
        $reflection = new ReflectionClass(UsersChecker::class);
        $property = $reflection->getProperty('api_key');
        $property->setAccessible(true);
        $property->setValue($this->checker, '');
        $this->model->expects($this->never())->method('getUsersToCheck');
        $this->model->expects($this->never())->method('updateUserMeta');

        $result = $this->scan([]);

        $this->assertSame([
            'html' => 'PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_BADKEY',
            'success' => false,
            'end' => true,
        ], $result);
        $this->assertSame([], UsersCheckerApiStub::$requests);
        $this->assertSame(0, UsersCheckerStorageStub::$instances);
    }

    public function testNormalScanPreservesRequestDataAndCounters()
    {
        $this->model->expects($this->once())->method('getUsersToCheck')->with(3)->willReturn([
            ['id' => 1, 'email' => 'clean@example.com'],
            ['id' => 2, 'email' => 'spam@example.com'],
            ['id' => 3, 'email' => ''],
        ]);
        $this->model->expects($this->exactly(2))->method('updateUserMeta')->withConsecutive(
            [1, 'ct_marked_as_spam', '0'],
            [2, 'ct_marked_as_spam', '1']
        );
        UsersCheckerApiStub::$responses = [[
            'clean@example.com' => ['appears' => '0'],
            'spam@example.com' => ['appears' => '1'],
        ]];
        UsersCheckerStorageStub::$settings['cleantalk_last_users_check'] = [
            'checking_count' => 5,
            'found_spam' => 2,
        ];

        $result = $this->scan(['limit' => 3, 'offset' => 7]);

        $this->assertSame([[
            'method_name' => 'spam_check_cms',
            'auth_key' => 'test-key',
            'data' => 'clean@example.com,spam@example.com,',
        ]], UsersCheckerApiStub::$requests);
        $this->assertTrue($result['success']);
        $this->assertSame(10, $result['offset']);
        $this->assertSame(8, $result['checkingCount']);
        $this->assertSame(3, $result['foundedSpam']);
        $this->assertSame(8, UsersCheckerStorageStub::$settings['cleantalk_last_users_check']['checking_count']);
    }

    public function testImprovedScanPreservesGroupingAndLastResponseHandling()
    {
        $this->model->method('getUsersToCheck')->willReturn([
            ['id' => 1, 'email' => 'first@example.com', 'registerDate' => '2024-01-01 10:00:00'],
            ['id' => 2, 'email' => 'second@example.com', 'registerDate' => '2024-01-02 10:00:00'],
            ['id' => 3, 'email' => 'third@example.com', 'registerDate' => '2024-01-02 11:00:00'],
        ]);
        $this->model->expects($this->exactly(2))->method('updateUserMeta')->withConsecutive(
            [2, 'ct_marked_as_spam', '1'],
            [3, 'ct_marked_as_spam', '0']
        );
        UsersCheckerApiStub::$responses = [
            ['first@example.com' => ['appears' => '1']],
            [
                'second@example.com' => ['appears' => '1'],
                'third@example.com' => ['appears' => '0'],
            ],
        ];
        UsersCheckerStorageStub::$settings['cleantalk_last_users_check'] = [
            'checking_count' => 5,
            'found_spam' => 2,
        ];

        $result = $this->scan(['improved_check' => true]);

        $this->assertSame([
            [
                'method_name' => 'spam_check_cms',
                'auth_key' => 'test-key',
                'data' => 'first@example.com',
                'date' => '2024-01-01',
            ],
            [
                'method_name' => 'spam_check_cms',
                'auth_key' => 'test-key',
                'data' => 'second@example.com,third@example.com',
                'date' => '2024-01-02',
            ],
        ], UsersCheckerApiStub::$requests);
        $this->assertTrue($result['success']);
        $this->assertSame(20, $result['offset']);
        $this->assertSame(2, $result['checkingCount']);
        $this->assertSame(1, $result['foundedSpam']);
        $this->assertCount(2, UsersCheckerStorageStub::$saved);
        $this->assertSame(0, UsersCheckerStorageStub::$saved[0]['checking_count']);
        $this->assertSame(0, UsersCheckerStorageStub::$saved[0]['found_spam']);
    }

    public function testNoUsersEndsScanWithoutApiRequest()
    {
        $this->model->method('getUsersToCheck')->willReturn([]);
        $this->model->expects($this->never())->method('updateUserMeta');
        UsersCheckerStorageStub::$settings['cleantalk_last_users_check'] = [
            'checking_count' => 8,
            'found_spam' => 2,
        ];

        $result = $this->scan(['offset' => 20]);

        $this->assertTrue($result['success']);
        $this->assertTrue($result['end']);
        $this->assertSame('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_NOUSERSTOCHECK', $result['html']);
        $this->assertSame(8, $result['checkingCount']);
        $this->assertSame(2, $result['foundedSpam']);
        $this->assertSame([], UsersCheckerApiStub::$requests);
        $this->assertSame([], UsersCheckerStorageStub::$saved);
    }

    /**
     * @dataProvider failedResponseProvider
     */
    public function testFailedApiResponseEndsScan($response, $message)
    {
        $this->model->method('getUsersToCheck')->willReturn([
            ['id' => 1, 'email' => 'test@example.com'],
        ]);
        $this->model->expects($this->never())->method('updateUserMeta');
        UsersCheckerApiStub::$responses = [$response];

        $result = $this->scan(['offset' => 20]);

        $this->assertFalse($result['success']);
        $this->assertTrue($result['end']);
        $this->assertSame($message, $result['html']);
        $this->assertArrayNotHasKey('offset', $result);
        $this->assertSame([], UsersCheckerStorageStub::$saved);
    }

    public function failedResponseProvider()
    {
        $common_error = 'PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_COMMON_ERROR';
        return [
            'false' => [false, $common_error],
            'empty array' => [[], $common_error],
            'null' => [null, $common_error],
            'true' => [true, $common_error],
            'string' => ['invalid response', $common_error],
            'API error' => [['error_message' => 'test error'], 'API error: test error'],
        ];
    }

    private function scan($data)
    {
        $reflection = new ReflectionClass(UsersChecker::class);
        $method = $reflection->getMethod('scan');
        $method->setAccessible(true);
        $response = $method->invoke($this->checker, $data);

        $this->assertIsString($response);
        $result = json_decode($response, true);
        $this->assertSame(JSON_ERROR_NONE, json_last_error());
        $this->assertIsArray($result);
        return $result;
    }
}

class UsersCheckerApiStub extends Api
{
    public static $requests = [];
    public static $responses = [];

    public static function sendRequest($data, $_url = self::URL, $timeout = 10, $ssl = false, $ssl_path = '')
    {
        self::$requests[] = $data;
        if (count(self::$responses) === 0) {
            throw new \LogicException('Unexpected API request.');
        }
        return array_shift(self::$responses);
    }
}

class UsersCheckerStorageStub implements StorageHandler
{
    public static $instances = 0;
    public static $settings = [];
    public static $saved = [];

    public function __construct()
    {
        self::$instances++;
    }

    public function getSetting($setting_name)
    {
        return isset(self::$settings[$setting_name]) ? self::$settings[$setting_name] : null;
    }

    public function saveSetting($setting_name, $setting_value)
    {
        self::$settings[$setting_name] = $setting_value;
        self::$saved[] = $setting_value;
    }

    public function deleteSetting($setting_name)
    {
        unset(self::$settings[$setting_name]);
    }

    public static function getUpdatingFolder()
    {
        throw new \LogicException('Unexpected updating folder lookup.');
    }

    public static function getJsLocation()
    {
        throw new \LogicException('Unexpected JavaScript location lookup.');
    }
}

class UsersCheckerTextStub
{
    public static function _($key)
    {
        return $key;
    }
}
