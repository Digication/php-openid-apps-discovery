Introduction
------------
This package extends JanRain's PHP OpenID library to support the discovery protocol
used by Google Apps for Your Domain.  It allows PHP apps using the library to
act as a relying party to any Google Apps domain.

Additional information on the discovery protocol can be found at:
http://groups.google.com/group/google-federated-login-api/web/openid-discovery-for-hosted-domains

Prerequisites
-------------
This requires the PHP OpenID library is installed.  The library can be found at 
http://openidenabled.com/php-openid/.  Refer to their documentation for detailed
instructions on installation and usage.

Installation
------------
Copy the included 'Auth' directory to a directory in your PHP include path.

Usage
-----
Once you've enabled OpenID with the PHP OpenID library, only a few minor changes to your code are
required to work with Google Apps.  Where constructing your Auth_OpenID_Consumer, make the following
changes:

1) Import the extension:
require_once 'Auth/OpenID/google_discovery.php'

2) Instantiate the helper class after creating your consumer.  For example:

   $consumer = new Auth_OpenID_Consumer($store);
   new GApps_OpenID_Discovery($consumer);
   
   ...
   
   $consumer->begin(...)
   
For Google Apps, the identifier used for the initial discovery is the domain name itself.  For example, prompting users to enter their email address to log in (e.g. jdoe@mycompany.com), only the domain portion (mycompany.com) should be supplied in $consumer->begin().  IDP endpoints for other OpenID providers can also be supplied.  If the supplied value is not recognized as a Google Apps domain the default discovery mechanisms are used instead.


Additional Options
------------------
The discovery protocol requires the validation of digital signatures.  A set of standard CA certificates are included and used by default.  If you choose to manage your own set of certificates, you can specify an array of files or directories containing your trusted roots when creating the helper.  For example:

    new GApps_OpenID_Discovery($consumer, array('/etc/ssl/certs'));

Refer to http://www.php.net/manual/en/openssl.cert.verification.php for further details.

You can also pass a memcache instance for caching discovery information. 

    $memcache = ...;
    new GApps_OpenID_Discovery($consumer, null, $memcache);
   
Using memcache is encouraged and speeds up logins for subsequent users coming from a domain.
