<?php
/*
Plugin Name: Password Hash Upgrade
Version: 1.0.0
Author: Alexander O'Mara
License: GPL-2.0-or-later
Description: Upgrade old password hashes to use modern PHP hashes.
*/

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Class to contain pasword hashing functions.
 */
class PASSWORD_HASH_UPGRADE {
	/**
	 * The password hash algorithm.
	 *
	 * @var int
	 */
	const HASH_ALGO = PASSWORD_DEFAULT;

	/**
	 * The phpass integer to ASCII 64 charset.
	 *
	 * @var string
	 */
	const PHPASS_ITOA64_CHARSET =
		'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

	/**
	 * Check if string starts with another.
	 *
	 * @param string $string The string to check.
	 * @param string $start The string to find.
	 * @return bool True if string starts with value, else false.
	 */
	public static function string_starts($string, $start) {
		return (substr($string, 0, strlen($start)) === $start);
	}

	/**
	 * The phpass base64 encoder implementation.
	 *
	 * @param string $input The data to encode.
	 * @param string $charset The charset to use to encode.
	 * @return string Encoded string.
	 */
	public static function phpass_encode64($input, $charset) {
		$count = strlen($input);

		$output = '';
		$i = 0;
		do {
			$value = ord($input[$i++]);
			$output .= $charset[$value & 0x3f];
			if ($i < $count) {
				$value |= ord($input[$i]) << 8;
			}
			$output .= $charset[($value >> 6) & 0x3f];
			if ($i++ >= $count) {
				break;
			}
			if ($i < $count) {
				$value |= ord($input[$i]) << 16;
			}
			$output .= $charset[($value >> 12) & 0x3f];
			if ($i++ >= $count) {
				break;
			}
			$output .= $charset[($value >> 18) & 0x3f];
		}
		while ($i < $count);

		return $output;
	}

	/**
	 * The phpass password hashing function.
	 *
	 * @param string $password Password in plain text to hash.
	 * @param string $setting An already hashed string including options.
	 * @param string $algo Hash algorithm.
	 * @return string|null Hashed password using options, or null on failure.
	 */
	public static function phpass_crypt($password, $setting, $algo) {
		$itoa64_charset = static::PHPASS_ITOA64_CHARSET;

		// Get the base 2 log and convert to integer.
		$count_log2 = strpos($itoa64_charset, $setting[3]);
		if ($count_log2 < 7 || $count_log2 > 30) {
			return null;
		}
		$count = 1 << $count_log2;

		// Hashes must have 8 character salt.
		$salt = substr($setting, 4, 8);
		if (strlen($salt) !== 8) {
			return null;
		}

		// Hash using specificed algorithm.
		$hash = hash($algo, $salt . $password, true);
		do {
			$hash = hash($algo, $hash . $password, true);
		}
		while (--$count);

		// If hashing failed, then checking failed.
		if (!$hash) {
			return null;
		}

		// Assemble into complete string, using same settings options.
		$output = substr($setting, 0, 12);
		$output .= static::phpass_encode64($hash, $itoa64_charset);

		return $output;
	}

	/**
	 * Check if a string, hashed with the specificed algorithm, matches.
	 *
	 * @param string $string The string to check.
	 * @param string $hash The existing hash to check against.
	 * @param string $algo The algorithm to apply.
	 * @return bool If matches then true, else false.
	 */
	public static function hashed_equals($string, $hash, $algo) {
		// Hash and return false on failure.
		$hashed = hash($algo, $string);
		if (!$hashed) {
			return false;
		}

		// Check that hashes match.
		return hash_equals($hash, $hashed);
	}

	/**
	 * Check if a hash string is a natively supported type.
	 *
	 * @param string $hash Hash string.
	 * @return bool If recognized as native hash, true, else false.
	 */
	public static function is_native($hash) {
		// Check if recognized by native function.
		$info = password_get_info($hash);
		if (isset($info) && is_int($info['algo']) && $info['algo']) {
			return true;
		}

		// Check if a native bcrypt hash with an alternate prefix.
		// Includes non-portable phpass hashes is bcrypt was used.
		// https://en.wikipedia.org/wiki/Crypt_(C)#Blowfish-based_scheme
		if (preg_match('/^\$2[a-zA-Z]*\$/', $hash)) {
			return true;
		}

		// Otherwise it must not be a native hash.
		return false;
	}

	/**
	 * Check if a hash string needs an upgrade.
	 *
	 * @param string $hash Hash string.
	 * @return bool If needs rehash, true, else false.
	 */
	public static function needs_upgrade($hash) {
		return password_needs_rehash($hash, static::HASH_ALGO);
	}

	/**
	 * Detect hash string type.
	 * If detected, returns array with base type, and possibly also a subtype.
	 * If not detect, null is returned.
	 *
	 * @param string $hash Hash string.
	 * @return string|null Detected type, else null.
	 */
	public static function type($hash) {
		// Check if native hash.
		if (static::is_native($hash)) {
			return 'native';
		}

		// Check if phpass hash.
		// $P$ = Standard prefix.
		// $H$ = phpBB3 prefix.
		if (
			static::string_starts($hash, '$P$') ||
			static::string_starts($hash, '$H$')
		) {
			return 'phpass';
		}

		// Check if a Drupal 7 hash.
		// $S$ = Drupal 7.
		if (static::string_starts($hash, '$S$')) {
			return 'drupal7';
		}

		// Check if it could be a bare hash.
		if (ctype_xdigit($hash)) {
			$len = strlen($hash);
			switch ($len) {
				case 32: {
					return 'md5';
				}
				case 40: {
					return 'sha1';
				}
				case 64: {
					return 'sha256';
				}
				case 128: {
					return 'sha512';
				}
			}
		}

		return null;
	}

	/**
	 * Hashes a password using the current hashing algorithm.
	 *
	 * @param string $password Plaintext password.
	 * @return string Hash string.
	 */
	public static function hash($password) {
		// Hash using native password hashing function.
		return password_hash($password, static::HASH_ALGO);
	}

	/**
	 * Verify a password against an existing hash string or bare hash.
	 * Supported hashes:
	 * - PHP 5.5+ native password hashing algorithms
	 * - Blowfish hashes (phpass in non-portable mode)
	 * - phpass hashes (phpass, WordPress, and phpBB3)
	 * - Drupal 7 hashes (based on phpass, but using SHA256)
	 * - MD5
	 * - SHA1
	 * - SHA256
	 * - SHA512
	 *
	 * @param string $password Plaintext password.
	 * @param string $hash Hash string.
	 * @return bool If matches then true, else false.
	 */
	public static function verify($password, $hash) {
		$type = static::type($hash);
		switch ($type) {
			case 'native': {
				return static::verify_native($password, $hash);
			}
			case 'phpass': {
				return static::verify_phpass($password, $hash);
			}
			case 'drupal7': {
				return static::verify_drupal7($password, $hash);
			}
			case 'md5': {
				return static::verify_md5($password, $hash);
			}
			case 'sha1': {
				return static::verify_sha1($password, $hash);
			}
			case 'sha256': {
				return static::verify_sha256($password, $hash);
			}
			case 'sha512': {
				return static::verify_sha512($password, $hash);
			}
		}
		return false;
	}

	/**
	 * Verify a PHP native password against an existing hash string.
	 *
	 * @param string $password Plaintext password.
	 * @param string $hash Hash string.
	 * @return bool If password matches, true, else false.
	 */
	public static function verify_native($password, $hash) {
		// If blowfish prefix has no letter, add one.
		if (substr($hash, 0, 3) === '$2$') {
			$hash = '$2a$' . substr($hash, 3);
		}

		// Check with native password varify function.
		return password_verify($password, $hash);
	}

	/**
	 * Verify a phpass password against an existing phpass hash string.
	 *
	 * @param string $password Plaintext password.
	 * @param string $hash Hash string.
	 * @return bool If password matches, true, else false.
	 */
	public static function verify_phpass($password, $hash) {
		// Hash and return false on failure.
		$hashed = static::phpass_crypt($password, $hash, 'md5');
		if (!$hashed) {
			return false;
		}
		// Check that hashes match.
		return hash_equals($hash, $hashed);
	}

	/**
	 * Verify a Drupal 7 password against an existing hash string.
	 *
	 * @param string $password Plaintext password.
	 * @param string $hash Hash string.
	 * @return bool If password matches, true, else false.
	 */
	public static function verify_drupal7($password, $hash) {
		// Hash and return false on failure.
		$hashed = static::phpass_crypt($password, $hash, 'sha512');
		if (!$hashed) {
			return false;
		}

		// Drupal 7 limits the number of characters in the hash.
		$hashed = substr($hashed, 0, 55);

		// Check that hashes match.
		return hash_equals($hash, $hashed);
	}

	/**
	 * Verify a bare MD5 hashed password against an existing hash.
	 *
	 * @param string $password Plaintext password.
	 * @param string $hash Hash string.
	 * @return bool If password matches, true, else false.
	 */
	public static function verify_md5($password, $hash) {
		return static::hashed_equals($password, $hash, 'md5');
	}

	/**
	 * Verify a bare SHA1 hashed password against an existing hash.
	 *
	 * @param string $password Plaintext password.
	 * @param string $hash Hash string.
	 * @return bool If password matches, true, else false.
	 */
	public static function verify_sha1($password, $hash) {
		return static::hashed_equals($password, $hash, 'sha1');
	}

	/**
	 * Verify a bare SHA256 hashed password against an existing hash.
	 *
	 * @param string $password Plaintext password.
	 * @param string $hash Hash string.
	 * @return bool If password matches, true, else false.
	 */
	public static function verify_sha256($password, $hash) {
		return static::hashed_equals($password, $hash, 'sha256');
	}

	/**
	 * Verify a bare SHA512 hashed password against an existing hash.
	 *
	 * @param string $password Plaintext password.
	 * @param string $hash Hash string.
	 * @return bool If password matches, true, else false.
	 */
	public static function verify_sha512($password, $hash) {
		return static::hashed_equals($password, $hash, 'sha512');
	}

	/**
	 * WordPress compatible implementation of hashing function.
	 *
	 * @param string $password Plaintext password.
	 * @return string Hash string.
	 */
	public static function wp_hash_password($password) {
		return static::hash($password);
	}

	/**
	 * WordPress compatible implementation of checking function.
	 *
	 * @param string $password Plaintext password
	 * @param string $hash Hash sting to check password against.
	 * @param string|int $user_id Optional user ID to update on hash upgrade.
	 * @return bool If password matches, true, else false.
	 */
	public static function wp_check_password($password, $hash, $user_id = '') {
		// Check if valid password.
		$check = static::verify($password, $hash);

		// If valid and user ID supplied, check if stored hash needs upgrade.
		if ($check && $user_id && static::needs_upgrade($hash)) {
			// Rehash password using a new hash.
			wp_set_password($password, $user_id);
			$hash = wp_hash_password($password);
		}

		return apply_filters(
			'check_password',
			$check,
			$password,
			$hash,
			$user_id
		);
	}
}

if (!function_exists('wp_hash_password')):
function wp_hash_password($password) {
	return PASSWORD_HASH_UPGRADE::wp_hash_password($password);
}
endif;

if (!function_exists('wp_check_password')):
function wp_check_password($password, $hash, $user_id = '') {
	return PASSWORD_HASH_UPGRADE::wp_check_password($password, $hash, $user_id);
}
endif;
