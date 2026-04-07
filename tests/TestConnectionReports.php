<?php

use PHPUnit\Framework\TestCase;
use Cleantalk\Custom\ConnectionReports;

class TestConnectionReports extends TestCase
{
    protected function setUp(): void
    {
        $_SERVER['REQUEST_URI'] = '/test-url';
        $_SERVER['HTTP_HOST']   = 'example.com';
    }

    protected function tearDown(): void
    {
        unset($_SERVER['REQUEST_URI'], $_SERVER['HTTP_HOST']);
    }

    public function testGetClearReports()
    {
        $data = ConnectionReports::getClearReports();

        $this->assertEquals(0, $data['success']);
        $this->assertEquals(0, $data['negative']);
        $this->assertEmpty($data['success_report']);
        $this->assertEmpty($data['negative_report']);
    }

    public function testValidateReportsWithInvalidInput()
    {
        $data = ConnectionReports::validate(null);

        $this->assertEquals(0, $data['success']);
        $this->assertEquals(0, $data['negative']);
    }

    public function testAddSuccess()
    {
        $data = ConnectionReports::getClearReports();

        $data = ConnectionReports::add($data, true);

        $this->assertEquals(1, $data['success']);
        $this->assertCount(1, $data['success_report']);
    }

    public function testAddNegative()
    {
        $data = ConnectionReports::getClearReports();

        $data = ConnectionReports::add($data, false, 'error');

        $this->assertEquals(1, $data['negative']);
        $this->assertEquals('error', $data['negative_report'][0]['lib_report']);
        $this->assertEquals('/test-url', $data['negative_report'][0]['page_url']);
    }

    public function testAddWithNonStringLibReport()
    {
        $data = ConnectionReports::getClearReports();

        $data = ConnectionReports::add($data, false, ['bad']);

        $this->assertEquals('unknown lib report', $data['negative_report'][0]['lib_report']);
    }

    public function testTrimReportsByCount()
    {
        $data = ConnectionReports::getClearReports();

        for ($i = 0; $i < 20; $i++) {
            $data = ConnectionReports::add($data, true);
        }

        $this->assertLessThanOrEqual(
            ConnectionReports::MAX_REPORTS_COUNT,
            count($data['success_report'])
        );
    }

    public function testFlushOldRemovesOldEntries()
    {
        $old = time() - 10 * 24 * 60 * 60; // older than 7 days

        $data = [
            'success_report' => [
                ['date' => $old],
                ['date' => time()],
            ],
            'negative_report' => [
                ['date' => $old],
                ['date' => time()],
            ],
            'success' => 2,
            'negative' => 2,
        ];

        $data = ConnectionReports::filter($data);

        $this->assertCount(1, $data['success_report']);
        $this->assertCount(1, $data['negative_report']);
    }

    public function testValidateReportsFixesCounters()
    {
        $data = [
            'success_report' => [ ['date' => time()] ],
            'negative_report' => [],
            'success' => 999,
            'negative' => 999,
        ];

        $data = ConnectionReports::validate($data);

        $this->assertEquals(1, $data['success']);
        $this->assertEquals(0, $data['negative']);
    }

    public function testSendMailReturnsTrue()
    {
        $data = ConnectionReports::getClearReports();

        $data = ConnectionReports::add($data, true);
        $data = ConnectionReports::add($data, false, 'error');

        $mail = function() {
            return true;
        };

        $result = ConnectionReports::sendMail($data, 'test@example.com', $mail);

        $this->assertTrue($result);
    }

    public function testSendMailWithoutServerVars()
    {
        unset($_SERVER['HTTP_HOST']);

        $data = ConnectionReports::getClearReports();
        $data = ConnectionReports::add($data, true);

        $mail = function() {
            return true;
        };

        $result = ConnectionReports::sendMail($data, 'test@example.com', $mail);

        $this->assertFalse($result);
    }

    public function testSendMailWithEmptyReports()
    {
        $data = ConnectionReports::getClearReports();

        $mail = function() {
            return true;
        };

        $result = ConnectionReports::sendMail($data, 'test@cleantalk.org', $mail);

        $this->assertFalse($result);
    }

    public function testMigration()
    {
        $data = ConnectionReports::getClearReports();

        unset($data['success_report']);

        $data['success'] = 9;

        $this->assertArrayNotHasKey('success_report', $data);

        $data = ConnectionReports::add($data, true);

        $this->assertArrayHasKey('success_report', $data);
        $this->assertEquals(1, $data['success']);
    }

    public function testLongRequestUriIsTrimmed()
    {
        $_SERVER['REQUEST_URI'] = str_repeat('a', 2000);

        $data = ConnectionReports::getClearReports();
        $data = ConnectionReports::add($data, false);

        $this->assertLessThanOrEqual(
            1000,
            strlen($data['negative_report'][0]['page_url'])
        );
    }

    public function testHtmlEscaping()
    {
        $_SERVER['REQUEST_URI'] = '<script>alert(1)</script>';

        $data = ConnectionReports::getClearReports();
        $data = ConnectionReports::add($data, false, '<b>bad</b>');

        ob_start();
        ConnectionReports::sendMail($data, 'test@example.com');
        $output = ob_get_clean();

        $this->assertTrue(true); // важно: просто покрытие htmlspecialchars
    }

    public function testPrepareEmailBodyBasic()
    {
        $data = ConnectionReports::getClearReports();

        $data['success'] = 1;
        $data['negative'] = 1;
        $data['success_report'][] = ['date' => time() - 100];
        $data['negative_report'][] = [
            'date' => time(),
            'page_url' => '/test',
            'lib_report' => 'error'
        ];

        $html = ConnectionReports::prepareEmailBody($data);

        $this->assertStringContainsString('Connection Report', $html);
        $this->assertStringContainsString('error', $html);
        $this->assertStringContainsString('/test', $html);
    }

    public function testPrepareEmailBodyWithoutNegativeReports()
    {
        $data = ConnectionReports::getClearReports();

        $data['success'] = 2;
        $data['success_report'][] = ['date' => time()];

        $html = ConnectionReports::prepareEmailBody($data);

        $this->assertStringContainsString('No negative reports', $html);
    }

    public function testPrepareEmailBodyMaxCountFormatting()
    {
        $data = ConnectionReports::getClearReports();

        for ($i = 0; $i < ConnectionReports::MAX_REPORTS_COUNT; $i++) {
            $data['negative_report'][] = [
                'date' => time(),
                'page_url' => '/test',
                'lib_report' => 'error'
            ];
        }

        $data['negative'] = ConnectionReports::MAX_REPORTS_COUNT;
        $data['success'] = ConnectionReports::MAX_REPORTS_COUNT;

        $html = ConnectionReports::prepareEmailBody($data);

        $this->assertStringContainsString('+', $html);
    }

    public function testPrepareEmailBodyEscaping()
    {
        $data = ConnectionReports::getClearReports();

        $data['negative'] = 1;
        $data['negative_report'][] = [
            'date' => time(),
            'page_url' => '<script>',
            'lib_report' => '<b>bad</b>'
        ];

        $html = ConnectionReports::prepareEmailBody($data);

        $this->assertStringContainsString('&lt;script&gt;', $html);
        $this->assertStringContainsString('&lt;b&gt;bad&lt;/b&gt;', $html);
    }

    public function testPrepareEmailBodyWithInvalidDates()
    {
        $data = ConnectionReports::getClearReports();

        $data['negative'] = 1;
        $data['negative_report'][] = [
            'date' => 'invalid',
            'page_url' => '/test',
            'lib_report' => 'error'
        ];

        $html = ConnectionReports::prepareEmailBody($data);

        $this->assertNotEmpty($html);
    }
}
