<?php
/**
 * A utility to hash and check hashes.
 * Tries to use the good stuff but is backwards compatible as needed
 */
class CryptHasher {
	
	//this should stay true, used for testing
	protected static $allowOpenssl = true;
	
	//this should stay true, used for testing
	protected static $allowMcrypt = true;
	
	/**
	 * Hash a password using the good stuff
	 * returns a string on success, false on error
	 * 
	 * @param $str string plaintext to hash
	 * @param $cost int minimum value seems to be 4, 10 is a good default
	 * @return string|boolean
	 */
	public static function hash($str, $cost = 10) {
		//init
		$phpversion = phpversion();
		
		//make sure we can blowfish
		if (!CRYPT_BLOWFISH) return false;
		
		//use different methods depending on php version
		if( version_compare($phpversion, '5.5.0', '>=')) $hash = self::get55Crypt($str, $cost);
		if( version_compare($phpversion, '5.3.7', '>=')) $hash = self::get53Crypt($str, $cost);
		else $hash = self::get52Crypt($str, $cost);
		
		//return hahs
		if( $hash === '*0' || $hash === '*1' ) return false;
		return $hash;
	}
	
	/**
	 * Check a hashed password
	 * Returns whehter the str_to_check matches the hash
	 * 
	 * @param $str_to_check string plaintext string
	 * @param $hashed_str string hashed string
	 * @return boolean
	 */
	public static function check($str_to_check, $hashed_str) {
		
		//backwards compatibility
		$doesntContainDollar = (strpos($hashed_str, '$') === false);
		if( $doesntContainDollar ) {
			$len = strlen($hashed_str);
			$salt = Configure::read('Security.salt');
			
			switch($len) {
				case 64:
					return (hash('sha256', $salt.$str_to_check) === $hashed_str);
				case 40:
					return (sha1($salt.$str_to_check) === $hashed_str);
				case 32:
					return (md5($salt.$str_to_check) === $hashed_str);
			}
			return false;
		}
		
		//the good hash
		return (crypt($str_to_check, $hashed_str) === $hashed_str);
	}
	
	/**
	 * Crypt for PHP > 5.5.0
	 * 
	 * @param $str string
	 * @param $cost int
	 * @return string
	 */
	protected static function get55Crypt($str, $cost) {
		$params = compact('cost');
		return @password_hash($str, PASSWORD_BCRYPT, $params);
	}
	
	/**
	 * Crypt for PHP < 5.3.7
	 * 
	 * @param $str string
	 * @param $cost int
	 * @return $string
	 */
	protected static function get52Crypt($str, $cost) {
		return self::hashWithCrypt($str, $cost, '2a');
	}
	
	/**
	 * Crypt for PHP > 5.3.7
	 * 
	 * @param $str string
	 * @param $cost int
	 * @return $string
	 */
	protected static function get53Crypt($str, $cost) {
		return self::hashWithCrypt($str, $cost, '2y');
	}
	
	/**
	 * Generate a hash using the "crypt" function
	 * 
	 * @param $str string
	 * @param $cost int
	 * @param $type string
	 * @return $string
	 */
	protected static function hashWithCrypt($str, $cost, $type) {
		//generate random salt
		//windows openssl is crazy slow
		if( self::$allowOpenssl && function_exists('openssl_random_pseudo_bytes')) {
			$salt = openssl_random_pseudo_bytes(22);
		}
		elseif( self::$allowMcrypt && function_exists('mcrypt_create_iv')) {
			$salt = mcrypt_create_iv(22);
		}
		else {
			//this is worst case scenario, not so secure
			$salt = sha1(mt_rand());
		}
		
		$salt = substr(base64_encode($salt), 0, 22);
		$salt = str_replace('+', '.', $salt);
		
		//cost is always 2 digits
		$cost = str_pad($cost, 2, '0', STR_PAD_LEFT);
		
		//built our params
		$params = '$' . implode('$', array($type, $cost, $salt));
		
		//run crypt
		return crypt($str, $params);
	}
	
}
