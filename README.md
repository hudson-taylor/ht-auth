# ht-auth

[![Build Status](https://travis-ci.org/SomeoneWeird/ht-auth.svg?branch=master)](https://travis-ci.org/SomeoneWeird/ht-auth)

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
