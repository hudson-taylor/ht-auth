# ht-auth

[![Build Status](https://travis-ci.org/hudson-taylor/ht-auth.svg?branch=master)](https://travis-ci.org/hudson-taylor/ht-auth)
[![Coverage Status](https://img.shields.io/coveralls/hudson-taylor/ht-auth/master.svg)](https://coveralls.io/r/hudson-taylor/ht-auth?branch=master)

`ht-auth` is a Hudson-Taylor service for managing users and authentication. It encapsulates best-practice for handling sensitive user information and logins.

Supports:

* User Registration
* Muliple password hashing algorithms
* Password Changing
* Password Resets
* 2 Factor Authentication
	* TOTP (Google Authenticator / Authy)
  * Yubikey
* Disable User Accounts

Coming Soon:

* HOTP Support
* OAuth Login Support
* SQL Backing support

# License

BSD, see `LICENSE.md`
