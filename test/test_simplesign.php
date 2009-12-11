<?php
require_once 'PHPUnit/Framework.php';
require_once 'fixtures.php';
require_once 'Auth/OpenID/DumbStore.php'; 
require_once 'Auth/OpenID/google_discovery.php';

class SimpleSignTest extends PHPUnit_Framework_TestCase {

    function setUp() {
        $this->fetcher =& Auth_Yadis_Yadis::getHTTPFetcher();
        $this->signer = new GApps_OpenID_SimpleSign();
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
        $authority = $this->signer->verify($xml, "euSfbCHW/sioRp++r8QKNsSUGM0p75q5CMPdbtnhPaBdBvX3eM90HiPAAg7N8fIqaY1z1xo8njNXuZXb"
            ."JIRmgXMCS34N6mKjtzwvkMgt2VlkADffN7DqEDoNcYXQ1l5xu+B4Cbxa9prTaItUr+wrnQ31kwlq6m5z9rTlZlcJlYE=");
        $this->assertEquals("hosted-id.google.com", $authority, "Invalid authority");
    }

    function test_verify_bad_signature() {
        $xml = GApps_Test_Fixtures::read_file('google-site-xrds.xml');
        try {
            $this->signer->verify($xml,"AGYbbl99vk2GoK4+HEBPuu6buV5YWMtX2fk5TNNTiMweXC+bibnJ6KqSqMVKz6IjB3S9ONbnTUdntJhdmlq"
                ."Q0Or9nTRjCPNz/bkEQ3/l0NOP4DMVbx5yhzp2QeZ86MNy9biD+Z6HsHl49X3puB8zBQ7vG2mIrJ+jE/cNZwCPNio=");
            $this->fail("Expected no authority");
        } catch (GApps_Discovery_Exception $e) {
        }
    }

}

/*
  
  

  

  }
*/
