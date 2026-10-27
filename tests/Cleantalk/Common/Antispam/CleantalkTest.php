<?php

namespace Cleantalk\Tests\Common\Antispam;

use Cleantalk\Common\Antispam\Cleantalk;
use Cleantalk\Common\Antispam\CleantalkRequest;
use Cleantalk\Common\Antispam\CleantalkResponse;
use Cleantalk\Tests\UnitCaseTools\HttpRequest;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class CleantalkTest extends \PHPUnit\Framework\TestCase
{
    protected $ct_request;

    protected $ct;

    protected function setUp(): void
    {
        require_once dirname(__DIR__, 3) . '/UnitCaseTools/HttpRequest.php';
        class_alias(HttpRequest::class, 'Cleantalk\Custom\Http\Request');
        HttpRequest::$requests = [];
        HttpRequest::$result = null;

        $this->ct = $this->getMockBuilder(Cleantalk::class)
            ->onlyMethods(['rotateModerate'])
            ->getMock();
        $this->ct->expects($this->never())->method('rotateModerate');
        $this->ct->work_url = 'https://moderate.example.test';
        $this->ct->server_changed = time();

        $this->ct_request = new CleantalkRequest();
        $this->ct_request->agent = 'unit-test';
        $this->ct_request->auth_key = 'test-key';
        $this->ct_request->sender_email = 'sender@example.test';
        $this->ct_request->message = 'test message';
    }

    /**
     * @dataProvider decisionProvider
     */
    public function testIsAllowUser($allow)
    {
        $this->assertModerationResponse('isAllowUser', 'check_newuser', $allow);
    }

    /**
     * @dataProvider decisionProvider
     */
    public function testIsAllowMessage($allow)
    {
        $this->assertModerationResponse('isAllowMessage', 'check_message', $allow);
    }

    public function decisionProvider()
    {
        return [
            'blocked' => [0],
            'allowed' => [1],
        ];
    }

    private function assertModerationResponse($method, $api_method, $allow)
    {
        HttpRequest::$result = json_encode([
            'allow' => $allow,
            'spam' => 1 - $allow,
            'comment' => 'Test moderation response',
        ]);

        $result = $this->ct->$method($this->ct_request);

        $this->assertInstanceOf(CleantalkResponse::class, $result);
        $this->assertSame($allow, $result->allow);
        $this->assertSame(1 - $allow, $result->spam);
        $this->assertSame(0, $result->errno);
        $this->assertSame('Test moderation response', $result->comment);
        $this->assertCount(1, HttpRequest::$requests);

        $request = HttpRequest::$requests[0];
        $this->assertSame('https://moderate.example.test/api2.0', $request['url']);
        $this->assertSame(['timeout' => 15], $request['options']);
        $data = json_decode($request['data'], true);
        $this->assertSame($api_method, $data['method_name']);
        $this->assertSame('test-key', $data['auth_key']);
        $this->assertSame('sender@example.test', $data['sender_email']);
        $this->assertSame('test message', $data['message']);
    }

    public function testHttpPingLocalhost()
    {
        $this->assertSame(0.001, $this->ct->httpPing('localhost'));
    }
}