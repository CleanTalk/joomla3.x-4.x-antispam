<?php

namespace Cleantalk\Common\Db;

use Cleantalk\Common\Templates\Singleton;

/**
 * CleanTalk abstract Data Base driver.
 * Shows what should be inside.
 * Uses singleton pattern.
 *
 * @version 1.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/php-antispam
 *
 * @psalm-suppress UnusedProperty
 * @psalm-suppress PossiblyUnusedProperty
 */
abstract class Db
{
	use Singleton;

    /**
     * @var string Query string
     */
    private $query;

    /**
     * @var array Processed result
     */
    public $result = array();

    /**
     * @var string Database prefix
     */
    public $prefix = '';

	/**
     * Alternative constructor.
     * Initialize Database object and write it to property.
     * Set tables prefix.
     */
    abstract protected function init();

    /**
     * Set $this->query string for next uses
     *
     * @param $query
     *
     * @return $this|void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function setQuery($query)
    {
	    $this->query = $query;
	    return $this;
    }

	public function getQuery()
	{
		return $this->query;
	}

    /**
     * Safely replace placeholders
     *
     * @param string $query
     * @param array $vars
     *
     * @return $this
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function prepare($query, $vars = array())
    {
	    $query = $query ?: $this->query;
	    $vars  = $vars ?: array();

	    $this->query = call_user_func($this->getPreparingMethod(), $query, $vars);

	    return $this;
    }

	/**
	 * @important This is very weak protection method
	 * @important Overload this method in CMS-based class
	 */
	public function getPreparingMethod()
	{
		return [$this, 'simplePreparingMethod'];
	}

	private function simplePreparingMethod($query, $vars)
	{
		array_walk($vars, function (&$item) {
			$item = '"' . addslashes($item) . '"';
		});
		return vsprintf($query, $vars);
	}

    public function prepareAndExecute($query, $vars = array())
    {
        $this->prepare($query, $vars);
        return $this->execute($this->query);
    }

    /**
     * Run any raw request
     *
     * @param $query string
     * @param $return_affected bool Need to the drupal class
     *
     * @return bool|int|void Raw result
     * @psalm-suppress PossiblyUnusedParam
     */
    abstract public function execute($query, $return_affected = false);

    /**
     * Fetchs first column from query.
     * May receive raw or prepared query.
     *
     * @param string $query
     * @param bool|string $response_type
     *
     * @return array|object|void|null
     * @psalm-suppress PossiblyUnusedMethod
     */
    abstract public function fetch($query, $response_type = false);

    /**
     * Fetchs all result from query.
     * May receive raw or prepared query.
     *
     * @param string $query
     * @param bool|string $response_type
     *
     * @return array|object|null|void
     * @psalm-suppress PossiblyUnusedMethod
     */
    abstract public function fetchAll($query = '', $response_type = false);

	public function getVar($query)
	{
		return array_values($this->fetch($query))[0];
	}

	abstract public function getAffectedRows();

    /**
     * Checks if the table exists
     *
     * @param $table_name
     *
     * @return bool
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function isTableExists($table_name)
    {
        return (bool)$this->execute("SHOW TABLES LIKE '" . $table_name . "'");
    }

    public function getLastError()
    {
        return 'Not implemented';
    }
}
