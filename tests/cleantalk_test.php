<?php

use Cleantalk\Common\Antispam\Cleantalk;
use Cleantalk\Common\Antispam\CleantalkRequest;

class cleantalk_test extends \PHPUnit\Framework\TestCase {

	protected $ct_request;

	protected $ct;

	protected function setUp()
	{
		$this->ct = new Cleantalk();
		$this->ct->server_url = 'https://moderate.cleantalk.org';
		$this->ct_request = new CleantalkRequest();
		$this->ct_request->agent = 'travis-ci';
		$this->ct_request->auth_key = getenv("CLEANTALK_TEST_API_KEY");
		$this->ct_request->sender_email = "s@cleantalk.org"; 
		$this->ct_request->message = "stop_word";
	}

	public function testIsAllowUser()
	{
		$result = $this->ct->isAllowUser($this->ct_request);
		$this->assertTrue($result->allow == 0);
	}

	public function testIsAllowMessage()
	{
		$result = $this->ct->isAllowMessage($this->ct_request);
		$this->assertTrue($result->allow == 0);
	}

    public function test_httpPing()
    {
    	$ct = new Cleantalk();
		$this->assertGreaterThan(0, $ct->httpPing("https://cleantalk.org/"));	
 	}
}