<?php

namespace Cleantalk\Common\Firewall;

class FwStats
{
    public $updating_id;
    public $updating_last_start = 0;
    public $update_percent = 0;
    public $update_period = 86400;
    public $updating_folder = 0;
    public $expected_networks_count = 0;
    public $expected_ua_count = 0;
    public $calls = 0;
    public $update_mode;
    public $last_update_time;
    public $last_update_way;
    public $entries;
    public $errors;
}
