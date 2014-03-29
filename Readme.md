Intro
=======================

This plugin tries to mimic much of the functionality of the "password_hash" function
built into PHP 5.5.  In fact, this plugin will use this native function if you do
have PHP 5.5+.

"password_hash" supports multi-round bcrypt as well as salt-per-password hashing which
makes for a much stronger hash that's highly resistant to most (all?) forms of attacks.

I'm not a crypto-geek, so if I've done something dumb, feel free to submit a push
request.

Version Support
=======================

Only CakePHP 2.4+ has the ability to define your own passwordHasher in the AuthComponent.
Versions of CakePHP below 2.4 are *not* supported by this plugin.

All versions of PHP that are supported by CakePHP 2.4+ should be supported by this plugin.
PHP version 5.3.7+ is recommended for the most secure passwords.  For PHP 5.2.x, having
the mcrypt PHP plugin is mandatory.

Backward Compatibly
=======================

This plugin tries to be backwards compatible with your existing "legacy" hashes. So if you
already have an established site that has sha1, md5, or sha256 hashes, then you
can use this plugin to slowly transition users to a more secure hash the next time
they change their password.

PHP versions 5.3.6 and below have a small vulnerability in its blowfish algorithms. In the
interest of security, this plugin is only forward compatible between PHP versions older than
5.3.7 and newer.  5.3.7 can validate 5.3.6 hashes, but 5.3.6 cannot validate 5.3.7 hashes.

Usage
=======================

When setting up the AuthComponent, define the custom password hasher to be used.

AppController.php
```PHP
public $components = array(
	'Auth'=>array(
		'authenticate'=>array(
			'Form'=>array(
				'passwordHasher'=>'CryptHasher.Crypt'
			)
		)
	)
);
```

When hashing a password to store in the database:
```PHP
App::uses('CryptHasher', 'CryptHasher.Lib');
$hashedPassword = CryptHasher::hash($plainTextPassword);
```

License
========================
MIT.  See LICENSE for details.  Please contribute back if you can.