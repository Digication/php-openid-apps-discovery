<?
/*
Copyright 2009 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Helper class for setting up Auth_OpenID_Consumer instances configured for
 * use with Google Apps as the default IDP.  Allows discovery of the IDP for
 * any Google Apps hosted domain by supplying just the domain name (e.g. 'acmecorp.com') 
 *
 * Implements the discovery protocol for Google Apps hosted domains described at
 * http://groups.google.com/group/google-federated-login-api/web/openid-discovery-for-hosted-domains
 *
 * Sample usage:
 *   // Initialize OpenID consumer
 *   $store = ...;
 *   $consumer = new Auth_OpenID_Consumer($store);
 *   // Enable Google Apps support
 *   $memcache = ...;
 *   $helper = new GApps_OpenID_Discovery($consumer, array('/etc/ssl/certs'), $memcache);
 *   // Use consumer
 *   $auth_request = $consumer->begin(...);
 */ 
class GApps_OpenID_Discovery {
    const DESCRIBED_BY_TYPE = 'http://www.iana.org/assignments/relation/describedby';
    const HOSTED_ID = 'hosted-id.google.com';
    const URI_TEMPLATE_ELEMENT = 'openid:URITemplate';
    const NEXT_AUTHORITY_ELEMENT = 'openid:NextAuthority';
    const USER_URI_VAR = '{%uri}';
    const CACHE_EXPIRY = 3600; // 1 hr
    const CACHE_PREFIX = '_gapps_openid_';
    
    var $host_meta_template = 'https://www.google.com/accounts/o8/.well-known/host-meta?hd=%s';
    var $memcache = null;
    var $verifier = null;

    /**
     * Initializes the helper and modifies the consumer instance to enable
     * OpenID discovery for Google Apps hosted domains. 
     *
     * 
     * @param Auth_OpenID_Consumer $consumer Consumer instance to enable
     * Google Apps support for.
     * @param array(str) $ca_dirs Array of directories containing trusted
     * root certificates (refer to OpenSSL documentation)
     * @param memcache $memcache Optional memcache handle for caching 
     * discovery information.
     */
    function GApps_OpenID_Discovery($consumer, $trust_roots, $memcache = null) {
        $this->verifier = new GApps_OpenID_SimpleSign($trust_roots);
        $this->memcache = $memcache;
        $consumer->discoverMethod = array($this, 'discover');
        $consumer->consumer->discoverMethod = array($this, 'discover');        
    }
    
    /**
     * Discovery implementation that supports Google Apps hosted domains.
     * This discovery method will fall back to Auth_OpenID_discover if the id is not
     * a valid Google Apps hosted domain.
     * 
     * @param str $url Either the domain name of the Google Apps domain or an OpenID id to discover
     * @param Auth_Yadis_HTTPFetcher &$fetcher HTTP client for fetching discovery information.
     * @return array(str,array(Auth_OpenID_ServiceEndpoint))
     */ 
    function discover($url, &$fetcher) {
        $endpoint = $this->perform_discovery($url, &$fetcher);
        if ($endpoint != null) {
            return $endpoint;
        }
        // Fallback to default discovery mechanism from php-openid
        return Auth_OpenID_discover($url, &$fetcher);
    }

    /**
     * Does either site discovery or user discovery depending on the url.  URLs
     * in the form http://domain.com/openid/... are treated as claimed IDs and
     * use the user discovery method outlined in the discovery algorihm docs.
     * 
     * Other values are treated as domain names and used for site discovery.
     *
     * @access private
     * @param str $url Either the domain name of the Google Apps domain or an OpenID id to discover
     * @param Auth_Yadis_HTTPFetcher &$fetcher HTTP client for fetching discovery information.
     * @return array(str,array(Auth_OpenID_ServiceEndpoint))
     */ 
    function &perform_discovery($url, &$fetcher) {
        if (preg_match('_^.*://(.*?)/.*_', $url, $matches)) {
            $domain = $matches[1];
            $claimed_id = $url;
            return $this->discover_user($domain, $claimed_id, &$fetcher);
        } 
        return $this->discover_site($url, &$fetcher);
    }

    /*
     * Handles the initial site discovery for a domain.
     *
     * @access private
     * @param str $url Domain name to perform discovery on
     * @param Auth_Yadis_HTTPFetcher &$fetcher HTTP client for fetching discovery information.
     * @return array(str,array(Auth_OpenID_ServiceEndpoint))
     */
    function &discover_site($domain, &$fetcher) {
        $url = $this->fetch_host_meta($domain, &$fetcher);
        $xrds =& $this->fetch_xrds_services($domain, $url, &$fetcher);
        if ($xrds != null) {
            $services = $xrds->services(array('filter_MatchesAnyOpenIDType'));
            $endpoints = Auth_OpenID_makeOpenIDEndpoints($domain, $services);
            return array($url, $endpoints);
        }
    }

    /*
     * Handles discovery for a user's claimed ID when verifying the response.
     *
     * @access private
     * @param str $domain Domain name to perform discovery on
     * @param str $claimed_id User's claimed id
     * @param Auth_Yadis_HTTPFetcher &$fetcher HTTP client for fetching discovery information.
     * @return array(str,array(Auth_OpenID_ServiceEndpoint))
     */
    function &discover_user($domain, $claimed_id, &$fetcher) {
        $site_url = $this->fetch_host_meta($domain, &$fetcher);
        $site_xrds =& $this->fetch_xrds_services($domain, $site_url, &$fetcher);
        if ($site_xrds == null) {
            return null;
        }
        list($user_url,$next_authority) = $this->get_user_xrds_url(&$site_xrds, $claimed_id);
        $user_xrds =& $this->fetch_xrds_services($next_authority, $user_url, &$fetcher);
        if ($user_xrds != null) {
            $services = $user_xrds->services(array('filter_MatchesAnyOpenIDType'));
            $endpoints = Auth_OpenID_makeOpenIDEndpoints($claimed_id, $services);
            return array($claimed_id, $endpoints);
        }
    }


    /*
     * Fetches the location of the site XRDS file, using the well known location
     * hosted by Google.  Returns a URL to the XRDS for the domain. 
     *
     * @access private
     * @param str $domain Domain name to perform discovery on
     * @param Auth_Yadis_HTTPFetcher &$fetcher HTTP client for fetching discovery information.
     * @return str
     */
    function fetch_host_meta($domain, &$fetcher) {
        $cached = $this->get_cache($domain);
        if ($cached != null) {
            return $cached;
        }
        $host_meta_url = sprintf($this->host_meta_template, $domain);
        $http_resp = @$fetcher->get($host_meta_url);
        if ($http_resp->status != 200 and $http_resp->status != 206) {
            return null;
        }
        if (!preg_match('/Link: <(.*)>;/', $http_resp->body, $matches)) {
            return null;
        }
        $url = $matches[1];
        $this->put_cache($domain, $url);
        return $url;
    }

    /*
     * Fetches and parses the XRDS from the specified login.
     *
     * @access private
     * @param str $authority Domain name that is authorative for the URL
     * @param str $url to fetch from
     * @param Auth_Yadis_HTTPFetcher &$fetcher HTTP client for fetching discovery information.
     * @return Auth_Yadis_XRDS
     */
    function &fetch_xrds_services($authority, $url, &$fetcher) {
        if ($url == null) {
            return null;
        }
        $body = $this->get_cache($url);
        if ($body == null) {
            $http_resp = @$fetcher->get($url);
            if ($http_resp->status != 200 and $http_resp->status != 206) {
                return null;
            }
            $body = $http_resp->body;
            $signature = $http_resp->headers["Signature"];
            if( $signature == null ) {
                return null;
            }
            $signed_by = $this->verifier->verify($body, $signature);
            if (!$signed_by) {
                return null;
            }
            if ($signed_by != strtolower($authority) && $signed_by != GApps_OpenID_Discovery::HOSTED_ID) {
                return false;
            }
            // Signature valid and signed by trusted root by this point.
            $this->put_cache($url,$body);
        }
        $xrds =& Auth_Yadis_XRDS::parseXRDS($body);
        return $xrds;
    }

    /*
     * Examines the site XRDS for the Google extension for getting the user XRDS location.
     * Returns a URL used to fetch the XRDS for the claimed ID.
     *
     * @access private
     * @param Auth_Yadis_XRDS &$xrds Service description to extract from
     * @param str $claimed_id User's claimed ID
     * @return aray(str)
     */
    function get_user_xrds_url(&$xrds, $claimed_id) {
        $types_to_match = array(GApps_OpenID_Discovery::DESCRIBED_BY_TYPE);
        foreach(@$xrds->services() as $service) {
            if ($service->matchTypes($types_to_match)) {
                $url = null;
                $authority = null;
                $elements = $service->getElements(GApps_OpenID_Discovery::URI_TEMPLATE_ELEMENT);
                if ($elements != null) {
                    $template = $elements[0]->textContent;
                    $url = str_replace(GApps_OpenID_Discovery::USER_URI_VAR, urlencode($claimed_id), $template);
                }
                $elements = $service->getElements(GApps_OpenID_Discovery::NEXT_AUTHORITY_ELEMENT);
                if ($elements != null) {
                    $authority = $elements[0]->textContent;
                }
                return array($url, $authority);
            }
        }
    }    
    
    /*
     * Helper for getting items from cache, if enabled.
     *
     * @access private
     * @param str $key Cache key
     * @return mixed
     */
    function get_cache($key) {
        if( $this->memcache == null ) {
            return null;
        }
        return $this->memcache->get(GApps_OpenID_Discovery::CACHE_PREFIX.$key);
    }
    
    /*
     * Helper for putting items in cache, if enabled.
     *
     * @access private
     * @param str $key Cache key
     * @param mixed $value Value to cache
     */
    function put_cache($key, $value) {
        if ($this->memcache != null) {
            $this->memcache->set(GApps_OpenID_Discovery::CACHE_PREFIX.$key, $value, 0, GApps_OpenID_Discovery::CACHE_EXPIRY);
        }
    }
}

/**
 * Handles signature verification of XRDS using XML Simple Sign.  This does not support the full range
 * of XML security options, only the subset required for the XML Simple Sign profile.
 */
class GApps_OpenID_SimpleSign {
    const C14N_RAW_OCTETS = 'http://docs.oasis-open.org/xri/xrd/2009/01#canonicalize-raw-octets';
    const SIGN_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    const NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#';
    const NS_XRDS = 'xri://$xrds';
    
    var $trust_roots;
    
    /**
     * Initialize with the location of trusted CAs.  Refer to OpenSSL docs for details
     * on managing trusted root certificates.
     *
     * @param array(mixed) $trust_roots Array of directories or files containing trusted CAs.
     */
    function GApps_OpenID_SimpleSign($trust_roots = null) {
        $this->trust_roots = $trust_roots;
    }

    /**
     * Parse an XML doc.
     *
     * @access private
     * @param str $xml XML text to parse
     * @return DOMDocument
     */
    function parseDoc($xml) {
        $doc = new DOMDocument();
        $doc->loadXML( $xml );
        return $doc;
    }

    /**
     * Gets an XPath processor for the given doc
     *
     * @access private
     * @param DOMDocument $doc Doc to process with XPath
     * @return DOMXPath
     */
    function getXpath($doc) {
        $xp = new DOMXPath($doc);
        $xp->registerNamespace("ds", GApps_OpenID_SimpleSign::NS_DSIG);
        $xp->registerNamespace("xrds", GApps_OpenID_SimpleSign::NS_XRDS);
        return $xp;
    }

    /**
     * Verifies the document is using supported canonicalization and signature methods.
     *
     * @access private
     * @param DOMXPath $xpath XPath processor for doc
     * @return bool
     */
    function validateXML($xpath) {
        $c14n = $xpath->query("//ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm")->item(0)->value;
        $algorithm = $xpath->evaluate("//ds:SignedInfo/ds:SignatureMethod/@Algorithm")->item(0)->value;
        if ($c14n != GApps_OpenID_SimpleSign::C14N_RAW_OCTETS) {
            // Only support XML SimpleSign
            return false;
        }
        if ($algorithm != GApps_OpenID_SimpleSign::SIGN_RSA_SHA1) {
            return false;
        }
        return true;
    }

    /**
     * Extract PEM encoded certificates from the XML signature.
     *
     * @access private
     * @param DOMXPath $xpath XPath processor for doc
     * @return array(str)
     */
    function parseCertificates($xpath) {
        $nodes = $xpath->query("//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()");
        $certs = array();
        foreach ($nodes as $node) {
            $cert = trim($node->wholeText);
            $cert = str_replace(array("\r", "\n"), "", $cert);
            $cert = chunk_split($cert, 64, "\n");
            $cert = "-----BEGIN CERTIFICATE-----\n".$cert."-----END CERTIFICATE-----\n";
            $certs[] = $cert;
        }
        return $certs;
    }

    /**
     * Save the certificate chain in the XML to a temp file.  Returns the name of the file.
     *
     * @access private
     * @param DOMXPath $xpath XPath processor for doc
     * @return str
     */
    function saveCertChain($certs) {
        $chain = implode("", $certs);
        $fname = tempnam(sys_get_temp_dir(), "cert");
        $handle = fopen($fname,"w");
        if ($handle) {
            fwrite($handle,$chain);
            fclose($handle);            
            return $fname;        
        }
    }

    /**
     * Verifies the signature of the document and that the signing certificate
     * stems from a trusted root CA.
     * 
     * Returns the CN of the signing certificate if valid.
     *
     * @param str $xml XML doc to verify
     * @param str $signature_value Base64 encoded signature to verify against.
     * @returns str
     */
    function verify($xml, $signature_value) {
        $doc = $this->parseDoc($xml);
        $xp = $this->getXPath($doc);
        
        $valid = $this->validateXML($xp);
        $certs = $this->parseCertificates($xp);
        
        $cert = openssl_x509_read($certs[0]);
        $pubkey = openssl_pkey_get_public($cert);
        $valid = openssl_verify($xml, base64_decode($signature_value), $pubkey);
        $signed_by = null;
        if ($valid) {
            // Since we may have multiple certs in the XML, save the chain to a temp file
            // so we an pass as a list of untrusted certs to verify. 
            $untrusted_file = $this->saveCertChain($certs);
            $trusted = openssl_x509_checkpurpose($certs[0], X509_PURPOSE_ANY, $this->trust_roots, $untrusted_file);
            if ($trusted) {
                $parsed_certificate = openssl_x509_parse($cert);
                $subject = $parsed_certificate["subject"];
                $signed_by = strtolower($subject["CN"]);
            }
            unlink($untrusted_file);
        }

        openssl_pkey_free($pubkey);
        openssl_x509_free($cert);
                
        return $signed_by;
    }    
}
?>