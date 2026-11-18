<?php

namespace Cleantalk\Tests\Custom\Db;

use Cleantalk\Custom\Db\Db;
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class DbTest extends TestCase
{
    private $errorLog;
    private $previousErrorLog;

    protected function setUp(): void
    {
        class_alias(DbFactoryStub::class, 'JFactory');
        $this->errorLog = tempnam(sys_get_temp_dir(), 'cleantalk-db-');
        $this->assertNotFalse($this->errorLog);
        $this->previousErrorLog = ini_set('error_log', $this->errorLog);
    }

    protected function tearDown(): void
    {
        ini_set('error_log', $this->previousErrorLog);
        unlink($this->errorLog);
    }

    public function testMissingQueryClearsStaleRowsWithoutAccessingDatabase()
    {
        $db = new Db();
        $db->result = [['stale' => 'row']];

        $this->assertNull($db->fetchAll());
        $this->assertSame([], $db->result);
        $this->assertSame([], DbFactoryStub::$queries);
        $this->assertSame(0, DbFactoryStub::$calls);
        $this->assertStringContainsString(
            'A SQL query must be provided or prepared before fetching rows.',
            file_get_contents($this->errorLog)
        );
    }

    /**
     * @dataProvider queryProvider
     */
    public function testExplicitAndStoredQueriesPreserveResults($explicit, $stored, $expected)
    {
        $db = new Db();
        if ($stored !== null) {
            $db->setQuery($stored);
        }
        DbFactoryStub::$rows = [['id' => 7]];

        $this->assertSame([['id' => 7]], $db->fetchAll($explicit));
        $this->assertSame([['id' => 7]], $db->result);
        $this->assertSame([$expected], DbFactoryStub::$queries);
        $this->assertSame('', file_get_contents($this->errorLog));
    }

    public function queryProvider()
    {
        return [
            'explicit' => ['SELECT 7', null, 'SELECT 7'],
            'stored' => [false, 'SELECT 8', 'SELECT 8'],
            'empty falls back to stored' => ['', 'SELECT 8', 'SELECT 8'],
            'explicit overrides stored' => ['SELECT 7', 'SELECT 8', 'SELECT 7'],
        ];
    }

    public function testDatabaseExecutionExceptionIsNotSuppressed()
    {
        DbFactoryStub::$exception = new \RuntimeException('Database execution failed.');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Database execution failed.');

        (new Db())->fetchAll('SELECT 7');
    }
}

class DbFactoryStub
{
    public static $calls = 0;
    public static $queries = [];
    public static $rows = [];
    public static $exception;

    public static function getDBO()
    {
        self::$calls++;
        return new DbDriverStub();
    }
}

class DbDriverStub
{
    public function setQuery($query)
    {
        DbFactoryStub::$queries[] = $query;
        return $this;
    }

    public function loadAssocList()
    {
        if (DbFactoryStub::$exception !== null) {
            throw DbFactoryStub::$exception;
        }
        return DbFactoryStub::$rows;
    }
}
