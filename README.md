# WordPress Password Hash Upgrade

A WordPress plugin to upgrade old password hashes to use modern PHP hashes

[![travis-ci](https://travis-ci.org/AlexanderOMara/wordpress-password-hash-upgrade.svg?branch=master)](https://travis-ci.org/AlexanderOMara/wordpress-password-hash-upgrade)


# Overview

A simple plugin that implements the pluggable `wp_hash_password` and `wp_check_password` functions to upgrade old hashes to modern PHP hashes.

**Supported hashes:**

-   PHP 5.5+ native password hashing algorithms
-   Blowfish hashes (phpass in non-portable mode)
-   phpass hashes (phpass, WordPress, and phpBB3)
-   Drupal 7 hashes (based on phpass, but using SHA256)
-   MD5
-   SHA1
-   SHA256
-   SHA512


# Installation

Copy `password-hash-upgrade.php` to your `wp-content/mu-plugins` directory (create directory if necessary).


# Bugs

If you find a bug or have compatibility issues, please open a ticket under issues section for this repository.


# License

Copyright (c) 2020 Alexander O'Mara

Licensed under GNU General Public License, version 2, or (at your option) any later version.

Portions of the code are based on Openwall's public domain phpass.
