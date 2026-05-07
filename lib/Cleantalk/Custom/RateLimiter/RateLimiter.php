<?php

namespace Cleantalk\Custom\RateLimiter;

use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\RateLimiter\RateLimiterConfig;
use Cleantalk\Common\RateLimiter\RateLimiterDto;
use Cleantalk\Common\Variables\Server;

class RateLimiter extends \Cleantalk\Common\RateLimiter\RateLimiter
{
    /**
     * @var string
     */
    private $table_name;
    /**
     * @var \Cleantalk\Common\Db\Db
     */
    private $db_object;

    public function __construct(RateLimiterConfig $config)
    {
        parent::__construct($config);
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $this->db_object = $db_class::getInstance();
        $this->table_name = $this->db_object->prefix . APBCT_RATE_LIMITS;
    }


    /**
     * @inheritDoc
     */
    protected function setIP(): void
    {
        /** @var \Cleantalk\Common\Helper\Helper $helper_class */
        $helper_class = Mloader::get('Helper');
        $this->ip = $helper_class::ipGet();
    }

    /**
     * @inheritDoc
     */
    protected function setUA(): void
    {
        $this->ua = (string) Server::get('HTTP_USER_AGENT', 'default_ua');
    }

    /**
     * @inheritDoc
     */
    protected function handleErrors(string $msg): void
    {
        error_log('CleanTalk RateLimiter error: ' . $msg);
    }

    /**
     * @inheritDoc
     */
    protected function increment(RateLimiterDto $uid_data): bool
    {
        $is_expired = ($this->current_ts - $uid_data->created_at) > $this->config->period;

        $uid_data->counter = $is_expired ? 1 : $uid_data->counter + 1;
        $uid_data->created_at = $is_expired ? $this->current_ts : $uid_data->created_at;
        $uid_data->last_call = $this->current_ts;

        $this->db_object->prepare(
            '
            UPDATE ' . $this->table_name . ' SET
                counter = %d,
                last_call = %d,
                created_at = %d
            WHERE uid = %s
        ', [
            $uid_data->counter,
            $uid_data->last_call,
            $uid_data->created_at,
            $uid_data->uid
        ]);

        return false !== $this->db_object->fetch($this->db_object->getQuery());
    }

    /**
     * @inheritDoc
     */
    protected function insert(RateLimiterDto $uid_data): bool
    {
        $this->db_object->prepare(
            '
            INSERT INTO ' . $this->table_name . '
                (uid, type, ip, ua, counter, last_call, created_at)
            VALUES (%s, %s, %s, %s, 1, %d, %d)
            ON DUPLICATE KEY UPDATE last_call = %s, counter = counter + 1;
            ',[
            $uid_data->uid,
            $uid_data->type,
            $uid_data->ip,
            $uid_data->ua,
            $uid_data->last_call,
            $uid_data->created_at,
            $uid_data->last_call
        ]);

        $result = $this->db_object->fetch($this->db_object->getQuery());

        return false !== $result;
    }

    /**
     * @inheritDoc
     */
    protected function cleanUp(): bool
    {
        $threshold = $this->current_ts - ($this->config->period + 10);

        $this->db_object->prepare(
            'DELETE FROM ' . $this->table_name . ' WHERE created_at < %d AND type = %s;',
            [
                $threshold,
                $this->config->type
            ]
        );

        $result = $this->db_object->fetch($this->db_object->getQuery());

        return false !== $result;
    }
}
