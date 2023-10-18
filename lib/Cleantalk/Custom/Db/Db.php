<?php

namespace Cleantalk\Custom\Db;

class Db extends \Cleantalk\Common\Db\Db
{
    /**
     * Alternative constructor.
     * Initilize Database object and write it to property.
     * Set tables prefix.
     */
    protected $dbResult;
    protected function init() {
        $this->prefix = \JFactory::getDBO()->getPrefix();
    }

    /**
     * Run any raw request
     *
     * @param $query
     *
     * @return bool|int Raw result
     */
    public function execute($query, $return_affected = false) {
        $this->dbResult = \JFactory::getDBO()->setQuery($query)->execute();
        return $this->dbResult;
    }

    /**
     * Fetches first column from query.
     * May receive raw or prepared query.
     *
     * @param string $query
     * @param bool $response_type
     *
     * @return array|object|void|null
     */
    public function fetch( $query = '', $response_type = false ) {
		$query = $this->getQuery() ?: $query;
        $this->result = \JFactory::getDBO()->setQuery($query)->loadAssoc();

        return $this->result;
    }

    /**
     * Fetchs all result from query.
     * May receive raw or prepared query.
     *
     * @param bool $query
     * @param bool $response_type
     *
     * @return array|object|null
     */
    public function fetchAll( $query = false, $response_type = false ) {
        $this->result = \JFactory::getDBO()->setQuery($query)->loadAssocList();

        return $this->result;
    }

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
        return (bool)$this->execute('SHOW TABLES LIKE "' . $table_name . '"');
    }

	public function getAffectedRows()
	{
		return \JFactory::getDBO()->getAffectedRows();
	}
}
