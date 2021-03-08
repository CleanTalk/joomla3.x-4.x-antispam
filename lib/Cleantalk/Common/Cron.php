<?php

namespace Cleantalk\Common;

/**
 * CleanTalk Cron class
 *
 * @package Antispam by CleanTalk
 * @Version 2.1.1
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

abstract class Cron
{
    public $debug = false;

    protected $tasks = array();           // Array with tasks
    protected $tasks_completed = array(); // Result of executed tasks
    
    // Option name with cron data
    const CRON_OPTION_NAME = 'cleantalk_cron';
    
    // Interval in seconds for restarting the task
    const TASK_EXECUTION_MIN_INTERVAL = 120;

    // Interval in seconds for cron work availability
    const CRON_EXECUTION_MIN_INTERVAL = 600;

    /**
     * Cron constructor.
     * Getting tasks option.
     */
    public function __construct()
    {
        if( time() - $this->getCronLastStart() > self::CRON_EXECUTION_MIN_INTERVAL ) {
            $this->tasks = $this->getTasks();
        }
    }

    /**
     * Get timestamp last Cron started.
     *
     * @return int timestamp
     */
    abstract public function getCronLastStart();

    /**
     * Save timestamp of running Cron.
     *
     * @return bool
     */
    abstract public function setCronLastStart();

    /**
     * Save option with tasks
     *
     * @param array $tasks
     * @return bool
     */
    abstract public function saveTasks( $tasks );
    
    /**
     * Getting all tasks
     *
     * @return array
     */
    abstract public function getTasks();
    
    /**
     * Adding new cron task.
     *
     * @param string $task
     * @param string $handler
     * @param int $period
     * @param null|int $first_call
     * @param array $params
     *
     * @return bool
     */
    public function addTask( $task, $handler, $period, $first_call = null, $params = array() )
    {
        // First call time() + period
        $first_call = ! $first_call ? time() + $period : $first_call;
        
        if( isset( $this->tasks[ $task ] ) ){
            return false;
        }
        
        // Task entry
        $this->tasks[$task] = array(
            'handler'   => $handler,
            'next_call' => $first_call,
            'period'    => $period,
            'params'    => $params,
        );
        
        return $this->saveTasks( $this->tasks );
    }
    
    /**
     * Removing cron task
     *
     * @param string $task
     *
     * @return bool
     */
    public function removeTask( $task )
    {
        if( ! isset( $this->tasks[ $task ] ) ){
            return false;
        }
        
        unset( $this->tasks[ $task ] );

        return $this->saveTasks( $this->tasks );
    }

    /**
     * Updates cron task, create task if not exists.
     *
     * @param string $task
     * @param string $handler
     * @param int $period
     * @param null|int $first_call
     * @param array $params
     *
     * @return bool
     */
    public function updateTask( $task, $handler, $period, $first_call = null, $params = array() )
    {
        $this->removeTask( $task );
        return $this->addTask( $task, $handler, $period, $first_call, $params );
    }
    
    /**
     * Getting tasks which should be run
     *
     * @return bool|array
     */
    public function checkTasks()
    {
        // No tasks to run
        if( empty( $this->tasks ) ){
            return false;
        }
        
        $tasks_to_run = array();
        foreach( $this->tasks as $task => &$task_data ){
            
            if(
                ! isset( $task_data['processing'], $task_data['last_call'] ) ||
                ( $task_data['processing'] === true && time() - $task_data['last_call'] > self::TASK_EXECUTION_MIN_INTERVAL )
            ){
                $task_data['processing'] = false;
                $task_data['last_call'] = 0;
            }
            
            if(
                $task_data['processing'] === false &&
                $task_data['next_call'] <= time() // default condition
            ){
                
                $task_data['processing'] = true;
                $task_data['last_call'] = time();
                
                $tasks_to_run[] = $task;
            }

            // Hard bug fix
            if( ! isset( $task_data['params'] ) ) {
                $task_data['params'] = array();
            }
            
        } unset( $task_data );

        $this->saveTasks( $this->tasks );

        return $tasks_to_run;
    }

    /**
     * Run all tasks from $this->tasks_to_run.
     * Saving all results to (array) $this->tasks_completed
     *
     * @param $tasks
     * @return void|array  Array of completed and uncompleted tasks.
     */
    public function runTasks( $tasks )
    {
        if( empty( $tasks ) ) {
            return;
        }

        if( ! $this->setCronLastStart() ) {
            return;
        }

        foreach( $tasks as $task ){

            if( function_exists( $this->tasks[$task]['handler'] ) ){

                if( $this->debug ) {
                    error_log( var_export( 'Task ' . $task . ' will be run.', 1 ) );
                }

                $result = call_user_func_array( $this->tasks[$task]['handler'], isset( $this->tasks[$task]['params'] ) ? $this->tasks[$task]['params'] : array() );

                if( $this->debug ) {
                    error_log( var_export( 'Result:', 1 ) );
                    error_log( var_export( $result, 1 ) );
                }

                if( empty( $result['error'] ) ){

                    $this->tasks_completed[$task] = true;

                    if( $this->tasks[$task]['period'] == 0 ) {
                        // One time scheduled event
                        unset( $this->tasks[$task] );
                    } else {
                        // Multi time scheduled event
                        $this->tasks[$task]['next_call'] = time() + $this->tasks[$task]['period'];
                    }

                }else{
                    $this->tasks_completed[$task] = false;
                    $this->tasks[$task]['next_call'] = time() + $this->tasks[$task]['period'] / 4;
                }

            }else{
                $this->tasks_completed[$task] = false;
            }

        }

        $this->saveTasks( $this->tasks );

        return $this->tasks_completed;
    }
}
