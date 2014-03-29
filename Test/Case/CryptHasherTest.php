<?php
App::uses('CryptHasher', 'CryptHasher.Lib');

/**
 * Allows us to get the protected functions.
 */
class CryptHasherFriend extends CryptHasher {
	
	public static function runFunc($func, $args) {
		return call_user_func_array(array('CryptHasherFriend', $func), $args);
	}
	
	public static function setVars($var, $value) {
		self::$$var = $value;
	}
	
}

/**
 * Crypt Hasher tests
 */
class CryptHasherTest extends CakeTestCase {
	
	protected $_testPasswords = array(
		'spider pig',
		'does whatever a spider pig does',
		'mmmm, donuts, eugggghhg',
		'you may remember me from such movies as'
	);
	
	/**
	 * when the test case starts
	 */
	public function setUp() {
		parent::setUp();
		
		if (!CRYPT_BLOWFISH) {
			$this->markTestSkipped('Blowfish not supported in your install');
		}
	}
	
	/**
	 * Before each test method
	 */
	public function startTest($method) {
		parent::startTest($method);
		CryptHasherFriend::setVars('allowOpenssl', true);
		CryptHasherFriend::setVars('allowMcrypt', true);
	}
	
	/**
	 * Make sure the crypt hashes are compatible with password_hash
	 */
	public function testBackwardsCompatHashing() {
		//cannot run this test if we're not running at least php 5.5
		if( version_compare(phpversion(), '5.5.0', '<')) {
			$this->markTestSkipped('PHP 5.5+ required to run this test case');
		}
		
		//try to test it
		foreach($this->_testPasswords as $plaintext) {
			$hash55 = CryptHasherFriend::runFunc('get55Crypt', array($plaintext, 10));
			$hash53 = CryptHasherFriend::runFunc('get53Crypt', array($plaintext, 10));
			$hash52 = CryptHasherFriend::runFunc('get52Crypt', array($plaintext, 10));
			
			$check = CryptHasherFriend::check($plaintext, $hash55);
			$this->assertTrue($check);
			$check = CryptHasherFriend::check($plaintext, $hash53);
			$this->assertTrue($check);
			$check = CryptHasherFriend::check($plaintext, $hash52);
			$this->assertTrue($check);
		}
	}
	
	/**
	 * Verify we can still verify sha1, md5, and sha256 hashes
	 */
	public function testLegacyHashVerify() {
		//init salt
		$oldsalt = Configure::read('Security.salt');
		$salt = 'j;viaeanjb;aie;';
		Configure::write('Security.salt', $salt);
		
		//verify all supported hash types
		foreach(array('sha1', 'md5', 'sha256') as $hashtype) {
			foreach($this->_testPasswords as $plaintext) {
				$hash = hash($hashtype, $salt.$plaintext);
				$check = CryptHasherFriend::check($plaintext, $hash);
				$this->assertTrue($check);
			}
		}
		
		//restore old salt
		Configure::write('Security.salt', $oldsalt);
	}
	
	/**
	 * Verify we can verify the passwords match
	 */
	public function testVerify() {
		//generate and check hashes
		foreach($this->_testPasswords as $plaintext) {
			$hash = CryptHasherFriend::hash($plaintext);
			$check = CryptHasherFriend::check($plaintext, $hash);
			$this->assertTrue($check);
		}
		
		//verify it properly fails matches too
		$hash = 'pig';
		foreach($this->_testPasswords as $plaintext) {
			$check = CryptHasherFriend::check($plaintext, $hash);
			$this->assertFalse($check);
			$hash = CryptHasherFriend::hash($plaintext);
		}
		
	}
	
	/**
	 * Test unique salt, every hash should be different
	 */
	public function testUniqueSalt() {
		foreach($this->_testPasswords as $plaintext) {
			$hashes = array();
			
			for($i = 0; $i < 10; ++$i) {
				$hashes[] = CryptHasherFriend::hash($plaintext);
			}
			
			$uniquehashes = array_unique($hashes);
			$this->assertEqual(count($uniquehashes), count($hashes));
		}
	}
	
	/**
	 * Make sure we can validate different costs
	 */
	public function testDifferentCosts() {
		foreach($this->_testPasswords as $plaintext) {
			//valid costs
			for($i = 0; $i < 5; ++$i) {
				$cost = mt_rand(4, 15);
				$hash = CryptHasherFriend::hash($plaintext, $cost);
				$check = CryptHasherFriend::check($plaintext, $hash);
				$this->assertTrue($check);
			}
			
			//invalid costs
			for($i = 0; $i < 4; ++$i) {
				$hash = CryptHasherFriend::hash($plaintext, $i);
				$check = CryptHasherFriend::check($plaintext, $hash);
				$this->assertFalse($check);
			}
		}
	}
	
	/**
	 * Make sure we can test openssl salts
	 */
	public function testOpensslSalt() {
		if( !function_exists('openssl_random_pseudo_bytes')) {
			$this->markTestSkipped('openssl_random_pseudo_bytes not supported');
		}
		
		$plaintext = current($this->_testPasswords);
		$hash = CryptHasherFriend::hash($plaintext);
		$check = CryptHasherFriend::check($plaintext, $hash);
		$this->assertTrue($check);
	}
	
	/**
	 * Make sure we can test mcrypt salts
	 */
	public function testMcryptSalts() {
		if( !function_exists('mcrypt_create_iv')) {
			$this->markTestSkipped('mcrypt_create_iv not supported');
		}
		
		CryptHasherFriend::setVars('allowOpenssl', false);
		CryptHasherFriend::setVars('allowMcrypt', true);
		
		$plaintext = current($this->_testPasswords);
		$hash = CryptHasherFriend::hash($plaintext);
		$check = CryptHasherFriend::check($plaintext, $hash);
		$this->assertTrue($check);
	}
	
	/**
	 * Make sure we can test mcrypt salts
	 */
	public function testFallbackSalts() {
		CryptHasherFriend::setVars('allowOpenssl', false);
		CryptHasherFriend::setVars('allowMcrypt', false);
		
		$plaintext = current($this->_testPasswords);
		$hash = CryptHasherFriend::hash($plaintext);
		$check = CryptHasherFriend::check($plaintext, $hash);
		$this->assertTrue($check);
	}
}
	