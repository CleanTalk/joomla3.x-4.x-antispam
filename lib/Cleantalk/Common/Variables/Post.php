<?php


namespace Cleantalk\Common\Variables;

/**
 * Class Post
 * Safety handler for $_POST
 *
 * @usage \Cleantalk\Variables\Post::get( $name );
 * @since 3.0
 * @package Cleantalk\Variables
 */
class Post extends ServerVariables{
	
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
	 * Gets given $_POST variable and save it to memory
	 * @param $name
	 *
	 * @return string       variable value or ''
	 */
	protected function get_variable( $name ){
		
		// Return from memory. From $this->variables
		if(isset(static::$instance->variables[$name]))
			return static::$instance->variables[$name];
		
		if( function_exists( 'filter_input' ) )
			$value = filter_input( INPUT_POST, $name );
		
		if( empty( $value ) )
			$value = isset( $_POST[ $name ] ) ? $_POST[ $name ]	: '';
		
		// Remember for further calls
		static::getInstance()->remebmer_variable( $name, $value );
		
		return $value;
	}
}