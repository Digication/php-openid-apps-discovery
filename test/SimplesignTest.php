<?php
require_once 'PHPUnit/Framework.php';
require_once 'fixtures.php';
require_once 'Auth/OpenID/DumbStore.php'; 
require_once 'Auth/OpenID/google_discovery.php';

class SimplesignTest extends PHPUnit_Framework_TestCase {

    function setUp() {
        $this->fetcher =& Auth_Yadis_Yadis::getHTTPFetcher();
        $this->signer = new GApps_OpenID_SimpleSign();
        
        $store = new Auth_OpenID_DumbStore("test");
        $consumer = new Auth_OpenID_Consumer($store);
        $this->discovery = new GApps_OpenID_Discovery($consumer);      
        $this->fetcher =& Auth_Yadis_Yadis::getHTTPFetcher();
        $this->discovery->perform_discovery("google.com", &$this->fetcher);      
    }
    
    function test_parse_certs_valid() {      
        $xml = GApps_Test_Fixtures::read_file('google-site-xrds.xml');
        $doc = $this->signer->parse_doc($xml);
        $xp = $this->signer->get_xpath($doc);
        $certs = $this->signer->parse_certificates($xp);
        $this->assertEquals(sizeof($certs), 2, "Expected 2 certificates");
    }

    function test_parse_no_certs() {
      $xml = GApps_Test_Fixtures::read_file('missing-signature.xml');
      $doc = $this->signer->parse_doc($xml);
      $xp = $this->signer->get_xpath($doc);
      $certs = $this->signer->parse_certificates($xp);
      $this->assertEquals(0, sizeof($certs), "Expected no certificates");
    }


    function test_parse_malformed_certs() {
        $xml = GApps_Test_Fixtures::read_file('malformed-cert.xml');
        $doc = $this->signer->parse_doc($xml);
        $xp = $this->signer->get_xpath($doc);
        try {
            $certs = $this->signer->parse_certificates($xp);
            $this->fail("Expected parse_certificates to fail");
        } catch (Exception $e) {            
        }
    }

    function test_validate_chain() {
      $xml = GApps_Test_Fixtures::read_file('google-site-xrds.xml');
      $doc = $this->signer->parse_doc($xml);
      $xp = $this->signer->get_xpath($doc);
      $certs = $this->signer->parse_certificates($xp);
      $this->assertTrue($this->signer->validate_chain($certs), "Cert chain should be valid");
    }

    function test_validate_broken_chain() {
        $xml = GApps_Test_Fixtures::read_file('broken-chain.xml');
        $doc = $this->signer->parse_doc($xml);
        $xp = $this->signer->get_xpath($doc);
        $certs = $this->signer->parse_certificates($xp);    
        $this->assertFalse($this->signer->validate_chain($certs), "Cert chain should not be valid");
    }

    function test_verify_signature_ok() {
        $xml = GApps_Test_Fixtures::read_file('google-site-xrds.xml');
        $authority = $this->signer->verify($xml, 
"OTMxjJnJlg+QOFDp23QfckMaXXvcImd0P6l9sgt86WNDwO1a0ajT9RFw6E0xSoEV6EkGLFP/a4SIBT6Px5cnzuM7Fa2ndJLgywVKnLfQPi78rSQ7rbl+c560GTZVO8jRJyg4DHduFs+ggiBHBA7SdtsseoEG1/1UhmCrA1JTpl0=");
        $this->assertEquals("hosted-id.google.com", $authority, "Invalid authority");
    }

    function test_verify_bad_signature() {
        $xml = GApps_Test_Fixtures::read_file('google-site-xrds.xml');
        try {
            $this->signer->verify($xml,
                "AGYbbl99vk2GoK4+HEBPuu6buV5YWMtX2fk5TNNTiMweXC+bibnJ6KqSqMVKz6IjB3S9ONbnTUdntJhdmlq" .
                "Q0Or9nTRjCPNz/bkEQ3/l0NOP4DMVbx5yhzp2QeZ86MNy9biD+Z6HsHl49X3puB8zBQ7vG2mIrJ+jE/cNZwCPNio=");
            $this->fail("Expected no authority");
        } catch (GApps_Discovery_Exception $e) {
        }
    }

    function test_verify_unsigned() {
        $xml = GApps_Test_Fixtures::read_file('missing-signature.xml');
        $authority = $this->signer->verify($xml, null);
        $this->assertEquals(null, $authority, "Authority for unsigned doc should be null");
    }

}

/*
  
  

  

  }
*/
