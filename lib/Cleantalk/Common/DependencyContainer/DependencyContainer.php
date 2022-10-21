<?php

namespace Cleantalk\Common\DependencyContainer;

use Cleantalk\Common\Templates\Singleton;

class DependencyContainer
{
    use Singleton;

    private $dep_map = [
        'Db'               => '\Cleantalk\Common\Db\DB',
        'Helper'           => '\Cleantalk\Common\Helper\Helper',
        'Api'              => '\Cleantalk\Common\Api\API',
        'State'            => '\Cleantalk\Common\State\State',
        'Queue'            => '\Cleantalk\Common\Queue\Queue',
        'Cron'             => '\Cleantalk\Common\Cron\Cron',
        'RemoteCalls'      => '\Cleantalk\Common\RemoteCalls\RemoteCalls',
        'StorageHandler'   => '\Cleantalk\Common\StorageHandler\StorageHandler',
    ];

    private $dependencies = [];

    public function get($dependency)
    {
        if ( ! isset($this->dependencies[$dependency]) ) {
            if ( isset($this->dep_map[$dependency]) ) {
                $dependency_obj = new $this->dep_map[$dependency]();
                $this->set($dependency, $dependency_obj);
            } else {
                throw new \RuntimeException('Loaded dependency ' . $dependency . ' is wrong.');
            }
        }
        return $this->dependencies[$dependency];

    }

    public function set($dependency, $dependency_obj)
    {
        if ( ! isset($this->dep_map[$dependency]) ) {
            throw new \RuntimeException('Added dependency ' . $dependency . ' is wrong.');
        }
        if ( ! $dependency_obj instanceof $this->dep_map[$dependency] ) {
            throw new \RuntimeException('Added dependency ' . $dependency . ' must implements ' . $this->dep_map[$dependency] . '.');
        }
        $this->dependencies[$dependency] = $dependency_obj;
    }
}
