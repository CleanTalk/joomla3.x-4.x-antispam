<?php

namespace Cleantalk\Tests\Custom\RateLimiter;

use Cleantalk\Common\Db\Db;
use Cleantalk\Common\RateLimiter\RateLimiterDto;
use Cleantalk\Custom\RateLimiter\RateLimiter;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class RateLimiterTest extends TestCase
{
    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testDtoCanBeAutoloadedWithCanonicalName()
    {
        $this->assertFalse(class_exists(RateLimiterDto::class, false));
        $this->assertTrue(class_exists(RateLimiterDto::class));

        $reflection = new ReflectionClass(RateLimiterDto::class);
        $this->assertSame(RateLimiterDto::class, $reflection->getName());
        $this->assertSame('RateLimiterDto.php', basename($reflection->getFileName()));
    }

    /**
     * @dataProvider uidDataProvider
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSelectUIDData($row)
    {
        $this->assertFalse(class_exists(RateLimiterDto::class, false));

        $db = $this->createMock(Db::class);
        $db->expects($this->once())
            ->method('prepare')
            ->with($this->stringContains('FROM test_rate_limits'), ['test-uid']);
        $db->method('getQuery')->willReturn('prepared query');
        $db->expects($this->once())
            ->method('fetch')
            ->with('prepared query')
            ->willReturn($row);

        $reflection = new ReflectionClass(RateLimiter::class);
        $limiter = $reflection->newInstanceWithoutConstructor();
        foreach (['db_object' => $db, 'table_name' => 'test_rate_limits', 'uid' => 'test-uid'] as $name => $value) {
            $property = $reflection->getProperty($name);
            $property->setAccessible(true);
            $property->setValue($limiter, $value);
        }

        $result = $limiter->selectUIDData();

        if (empty($row)) {
            $this->assertFalse($result);
        } else {
            $this->assertInstanceOf(RateLimiterDto::class, $result);
            $this->assertTrue($result->data_ok);
            foreach ($row as $name => $value) {
                $this->assertSame($value, $result->$name);
            }
        }
    }

    public function uidDataProvider()
    {
        return [
            'existing record' => [[
                'uid' => 'test-uid',
                'type' => 'set_alt_cookies',
                'ip' => '127.0.0.1',
                'ua' => 'test-agent',
                'counter' => 1,
                'last_call' => 1700000000,
                'created_at' => 1700000000,
            ]],
            'missing record' => [[]],
        ];
    }
}
