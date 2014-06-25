Server Auth Modules
===================

Implementations of ServerAuthModule.

* HttpHeaderAuthModule

  Uses HTTP Header data to authenticate a user.  Primarily used in SSO 
  implementations that add HTTP headers such as SiteMinder and Apache
  reverse proxy
  
* OAuthServerAuthModule

  Abstract implementation of the OAuth 2.0 Login.
  
* OpenIDConnectServerAuthModule

  OAuth 2.0 Login where the configuration is done though Open ID connect
  discovery URL.
  
* GoogleServerAuthModule

  OAuth 2.0 Login where the configuration is done though Google where the
  discovery data is loaded into the JAR to reduce network I/O.

  