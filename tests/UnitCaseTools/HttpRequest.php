<?php

namespace Cleantalk\Tests\UnitCaseTools;

class HttpRequest extends \Cleantalk\Common\Http\Request
{
    public static $result;
    public static $requests = [];

    public function request()
    {
        self::$requests[] = [
            'url' => $this->url,
            'data' => $this->data,
            'options' => $this->options,
        ];

        return self::$result;
    }
}
