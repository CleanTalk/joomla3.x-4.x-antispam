<?php
define('CLEANTALK_TEST_API_KEY', 'CleanTalk some api key');
require_once 'classes/Cleantalk.php';
require_once 'classes/CleantalkRequest.php';

class cleantalk_test extends \PHPUnit\Framework\TestCase {

	protected $ct_request;

	protected $ct;

	protected function setUp()
	{
		$this->ct = new Cleantalk();
		$this->ct_request = new CleantalkRequest();
		$this->ct_request->agent = 'travis-ci';
		$this->ct_request->auth_key = self::CLEANTALK_TEST_API_KEY;
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
		$this->assertInternalType("int",$ct->httpPing("https://cleantalk.org/"));
		$this->assertGreaterThan(0, $ct->httpPing("https://cleantalk.org/"));	
 	}
 	
    public function test_is_JSON()
    {
    	$ct = new Cleantalk();
		$isJson = '{
		"name":"John",
		"age":30,
		"cars":[ "Ford", "BMW", "Fiat" ]
		}';
		$notJson = "simple_str";
		$this->assertTrue($ct->is_JSON($isJson));
		$this->assertFalse($ct->is_JSON($notJson));	
 	} 	
}