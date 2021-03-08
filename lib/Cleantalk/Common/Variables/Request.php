<?php

namespace Cleantalk\Common\Variables;

/**
 * Class Request
 * Safety handler for $_REQUEST
 *
 * @usage \Cleantalk\Variables\Request::get( $name );
 * @since 3.0
 * @package Cleantalk\Variables
 */
class Request extends ServerVariables{
	
	static $instance;
	
	/**
	 * Constructor
	 * @return $this
	 */
	public static function getInstance(){
		if (!isset(static::$instance)) {
			static::$instance = new static;
			static::$instance->init();
		}
		return static::$instance;
	}
	
	/**
	 * Gets given $_REQUEST variable and save it to memory
	 * @param $name
	 *
	 * @return string       variable value or ''
	 */
	protected function get_variable( $name ){
		
		// Return from memory. From $this->variables
		if(isset(static::$instance->variables[$name]))
			return static::$instance->variables[$name];
		
		$value = isset( $_REQUEST[ $name ] ) ? $_REQUEST[ $name ]	: '';
		
		// Remember for further calls
		static::getInstance()->remebmer_variable( $name, $value );
		
		return $value;
	}
}