<?php

error_reporting(E_ALL);
define('ABSPATH', __DIR__);

require_once(__DIR__ . '/../password-hash-upgrade.php');

$test_failed = false;
$tests_completed = [
	'pass' => 0,
	'fail' => 0
];

/**
 * Perform test.
 *
 * @param bool $test Value to check true.
 * @param string $message Message for the test.
 */
function test($test, $message) {
	global $tests_completed;

	$tests_completed[$test ? 'pass' : 'fail']++;

	echo ($test ? 'PASS' : 'FAIL') . ": $message\n";
}

/**
 * End tests.
 */
function test_end() {
	global $tests_completed;

	$passed = $tests_completed['pass'];
	$failed = $tests_completed['fail'];
	echo "\nPASSED: $passed\nFAILED: $failed\n";
	exit($failed ? 1 : 0);
}

$hash_units = [
	'test' => [
		'native' => [
			'$2y$10$U80mJUgaGb7wSSiRRKn23evf7XrmZ29x0o/SN4Cv5/9LUz.n2lkuu',
			'$2$08$dAcT26qxNgg5bf1bz2.KyuQ8F/cLkDZillSCe2z5C5f/4cZALMdv2',
			'$2a$08$dAcT26qxNgg5bf1bz2.KyuQ8F/cLkDZillSCe2z5C5f/4cZALMdv2',
			'$2b$08$dAcT26qxNgg5bf1bz2.KyuQ8F/cLkDZillSCe2z5C5f/4cZALMdv2',
			'$2x$08$dAcT26qxNgg5bf1bz2.KyuQ8F/cLkDZillSCe2z5C5f/4cZALMdv2',
			'$2y$08$dAcT26qxNgg5bf1bz2.KyuQ8F/cLkDZillSCe2z5C5f/4cZALMdv2'
		],
		'phpass' => [
			'$P$BTt2O9vHUm3ebZWWPBMKpQxoHsR2Ef1',
			'$H$BTt2O9vHUm3ebZWWPBMKpQxoHsR2Ef1'
		],
		'drupal7' => [
			'$S$DxtmXMM8LNXg9WtRpOiGqc0pBrS1nzBHF2n3QHYviXbJ7DRwwQLE'
		],
		'md5' => [
			'098f6bcd4621d373cade4e832627b4f6'
		],
		'sha1' => [
			'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'
		],
		'sha256' => [
			'9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
		],
		'sha512' => [
			'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db2' .
			'7ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'
		]
	]
];

$set_password_hook = null;

/**
 * Dummy implementation.
 *
 * @param string $password Filter type.
 * @param string|int $user_id  Optional user ID to update on hash upgrade.
 */
function wp_set_password($password, $user_id) {
	global $set_password_hook;

	if ($set_password_hook) {
		call_user_func($set_password_hook, func_get_args());
	}
}

/**
 * Dummy implementation.
 *
 * @param mixed $hook Callback function or null.
 */
function set_wp_set_password_hook($hook) {
	global $set_password_hook;

	$set_password_hook = $hook;
}

$filter_hook = null;

/**
 * Dummy implementation.
 *
 * @param string $type Filter type.
 * @param mixed $value The value to filter.
 * @return mixed Filtered value.
 */
function apply_filters($type, $value) {
	global $filter_hook;

	if ($filter_hook) {
		call_user_func($filter_hook, func_get_args());
	}
	return $value;
}

/**
 * Dummy implementation.
 *
 * @param mixed $hook Callback function or null.
 */
function set_apply_filter_hook($hook) {
	global $filter_hook;

	$filter_hook = $hook;
}

/**
 * Test wp_hash_password.
 */
function test_wp_hash_password() {
	test(
		password_verify('test', wp_hash_password('test')),
		'password_verify "test" matches "test"'
	);
	test(
		!password_verify('fail', wp_hash_password('test')),
		'password_verify "fail" failed to match "test"'
	);
}
test_wp_hash_password();

/**
 * Test wp_hash_password.
 */
function test_wp_check_password() {
	global $hash_units;

	// Test that the hash functions pass and fail as expected.
	foreach ($hash_units as $password=>$types) {
		foreach ($types as $type=>$hashes) {
			foreach ($hashes as $hash_i=>$hash) {
				test(
					wp_check_password($password, $hash),
					"$password: $type: [$hash_i] (valid)"
				);
				test(
					!wp_check_password("_$password", $hash),
					"$password: $type: [$hash_i] (invalid)"
				);
			}
		}
	}
}
test_wp_check_password();

/**
 * Test wp_hash_password filters.
 */
function test_wp_check_password_filters() {
	global $hash_units;

	// Check that filters are called correctly.
	$sample_pass = 'test';
	$sample_md5 = $hash_units[$sample_pass]['md5'][0];
	$filter_args = [];
	set_apply_filter_hook(function($args) use (&$filter_args) {
		$filter_args[] = $args;
	});
	wp_check_password($sample_pass, $sample_md5);
	set_apply_filter_hook(null);

	$expected_filter_args = [
		['check_password', true, 'test', $sample_md5, '']
	];

	test($filter_args === $expected_filter_args, 'Got expected filter args');
}
test_wp_check_password_filters();

/**
 * Test wp_hash_password upgrade.
 */
function test_wp_check_password_upgrade() {
	global $hash_units;

	$sample_id = 42;
	$sample_pass = 'test';
	$sample_md5 = $hash_units[$sample_pass]['md5'][0];

	// Check that not called when no ID specficied.
	$set_called = false;
	set_wp_set_password_hook(function($args) use (&$set_called) {
		$set_called = true;
	});
	wp_check_password($sample_pass, $sample_md5);
	set_wp_set_password_hook(null);

	test(!$set_called, 'Update not called when no ID');

	// Check that is called when ID is specficied.
	$set_args = [];
	set_wp_set_password_hook(function($args) use (&$set_args) {
		$set_args[] = $args;
	});
	wp_check_password($sample_pass, $sample_md5, $sample_id);
	set_wp_set_password_hook(null);

	$expected_set_args = [
		['test', 42]
	];

	test($set_args === $expected_set_args, 'Got expected set args');


	// Check that is called when ID is specficied.
	$set_args = [];
	set_wp_set_password_hook(function($args) use (&$set_args) {
		$set_args[] = $args;
	});
	wp_check_password(
		$sample_pass,
		PASSWORD_HASH_UPGRADE::hash($sample_pass),
		$sample_id
	);
	set_wp_set_password_hook(null);

	$expected_set_args = [
		['test', 42]
	];

	test($set_args === [], 'Update not called on up-to-date hash');
}
test_wp_check_password_upgrade();

test_end();
