<?php

namespace Cleantalk\Common\StorageHandler;

use Cleantalk\Common\Templates\Singleton;

abstract class StorageHandler
{
    use Singleton;

    public static function get($option_name) {
        return static::getInstance()->getOption($option_name);
    }

    public static function set($option_name, $option_value) {
        return static::getInstance()->setOption($option_name, $option_value);
    }

    abstract protected function getOption($option_name);

    abstract protected function setOption($option_name, $option_value);
}
