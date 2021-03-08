<?php

namespace Cleantalk\Common\Variables;

/**
 * Class Get
 * Safety handler for $_GET
 *
 * @usage \Cleantalk\Variables\Get::get( $name );
 * @since 3.0
 * @package Cleantalk\Variables
 */
class Get extends ServerVariables{
	
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
	 * Gets given $_GET variable and save it to memory
	 * @param $name
	 *
	 * @return string       variable value or ''
	 */
	protected function get_variable( $name ){
		
		// Return from memory. From $this->variables
		if(isset(static::$instance->variables[$name]))
			return static::$instance->variables[$name];
		
		if( function_exists( 'filter_input' ) )
			$value = filter_input( INPUT_GET, $name );
		
		if( empty( $value ) )
			$value = isset( $_GET[ $name ] ) ? $_GET[ $name ]	: '';
		
		// Remember for further calls
		static::getInstance()->remebmer_variable( $name, $value );
		
		return $value;
	}
}