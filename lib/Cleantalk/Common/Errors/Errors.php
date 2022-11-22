<?php

namespace Cleantalk\Common\Errors;

use Cleantalk\Common\Templates\Singleton;

/**
 * Class Err
 * Uses singleton template.
 * Errors handling
 */
class Errors
{
	use Singleton;

	private $errors = [];
	
	/**
	 * Adds new error
	 *
	 */
	public static function add(){
		self::getInstance()->errors[] = implode(': ', func_get_args());
		return self::$instance;
	}

	public function append( $string ){
		$this->errors[ count( $this->errors ) - 1 ] = $string . ': ' . end( self::getInstance()->errors );
	}
	
	public static function prepend( $string ){
		$str = array_pop( self::$instance->errors );
		array_push( self::$instance->errors, $string . ': ' . $str );
	}
	
	public static function getLast( $output_style = 'bool' ){
		$out = (bool) self::$instance->errors;
		if( $output_style === 'as_json'){
            $out = json_encode( array( 'error' => end( self::$instance->errors ) ), true );
        }
		if( $output_style === 'string'){
            $out = array( 'error' => end( self::$instance->errors ) );
        }
		return $out;
	}
	
	public static function getAll( $output_style = 'string' ){
		$out = self::$instance->errors;
		if( $output_style === 'as_json'){
            $out = json_encode( self::$instance->errors, true );
        }
		return $out;
	}
	
	public static function check(){
		return (bool)self::$instance->errors;
	}
	
	public static function checkAndOutput( $output_style = 'string' ){
		if(self::check()) {
			return self::getLast($output_style);
		}
		else {
			return false;
		}
	}
}
