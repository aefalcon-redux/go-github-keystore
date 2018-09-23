# go-github-keystore
Key store for github apps written in go

Introduction
------------

This collection of software manages RSA keys and access tokens for
github applications.  There are three pieces of software meant to be
used directly:

  1.  __gh-keystore-admin__ is a command line tool for managing
      application RSA keys stored in s3.
  2.  __lambda/getappjwt__ is an AWS lambda function that can sign
      claims for a JSON Web Token using RSA keys stored in S3.
  3.  __lambda/getinstalltoken__ is an AWS lambda function that
      fetches and caches installation access tokens using S3 for storage.
      It itself invokes __lambda/getappjwt__.


Notes on the remaining modules are below:

  * __appkeystore__: Logic for managing application RSA keys stored in
    a messagestore
  * __keyservice__: Interface definitions for managing and using
    application keys
  * __keyutils__: Shared functions for RSA keys
  * __kslog__: Logging interface; can wrap both log.Logger and
    testing.T
  * __lambdacall__: Call services which are lambda functions
  * __messagestore__: A store for protocol buffer messages
  * __s3store__: A messagestore using S3
  * __timeutils__: Shared time functions
  * __tokenservice__:  Interface for accessing tokens
  * __tokenstore__ Logic for managing a token store


Implementation Notes
--------------------
If there is a burst of token requests for the same installation token
and a valid one is not already cached, several tokens may be requested
from github each subtracting from your quota total.

Multiple writes to the keystore may leave it it inconsistent because
S3 itself offers no consistency guarantee for updates.  An improved
implementation could store canonical data to dynamodb and have a
read-only version in S3.
