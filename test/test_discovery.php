<?php
require_once 'PHPUnit/Framework.php';
require_once 'fixtures.php';
require_once 'Auth/OpenID/DumbStore.php'; 
require_once 'Auth/OpenID/google_discovery.php';

class DiscoveryTest extends PHPUnit_Framework_TestCase {

    protected function setUp() {
        $store = new Auth_OpenID_DumbStore("test");
        $consumer = new Auth_OpenID_Consumer($store);
        $this->discovery = new GApps_OpenID_Discovery($consumer);      
        $this->fetcher =& Auth_Yadis_Yadis::getHTTPFetcher();
    }
  
    function test_fetch_host_meta() {
        $url = $this->discovery->fetch_host_meta("google.com", &$this->fetcher);
        $this->assertNotNull($url, "Should have found link for google.com");
    }  
  
    function test_fetch_no_host_meta() {
        try {
            $url = $this->discovery->fetch_host_meta("___NOT_A_VALID_DOMAIN__.com", $this->fetcher);   
            $this->fail("Discovery should have failed.");
        } catch (GApps_Discovery_Exception $e) {}
    }
    
    function test_fetch_xrds() {
        $url = $this->discovery->fetch_host_meta("google.com", &$this->fetcher);
        $xrds = $this->discovery->fetch_xrds_services("google.com", $url, &$this->fetcher);
        $this->assertNotNull($xrds, "Should have found XRDS for google.com");    
    }
    
    function test_get_user_xrds_url() {
        $xml = GApps_Test_Fixtures::read_file("google-site-xrds.xml");
        $xrds =& Auth_Yadis_XRDS::parseXRDS($xml);
        list($url, $next_authority) = $this->discovery->get_user_xrds_url($xrds, "http://google.com/openid?id=12345");
        $this->assertTrue(strcasecmp($next_authority, "hosted-id.google.com") == 0, "Expected $next_authority to be hosted-id.google.com");
        $this->assertTrue(strcasecmp($url,
            "https://www.google.com/accounts/o8/user-xrds?uri=http%3A%2F%2Fgoogle.com%2Fopenid%3Fid%3D12345") == 0);
    }

    function test_site_discover() {
        $info = $this->discovery->perform_discovery("google.com", &$this->fetcher);
        $this->assertNotNull($info); 
    }
  
    function test_user_discover() {
        $info = $this->discovery->perform_discovery("http://google.com/openid?id=109052429299753016317", &$this->fetcher);
        $this->assertNotNull($info);
    }
    
    function test_fail_discover() {
        try {
            $info = $this->discovery->perform_discovery("yahoo.com", &$this->fetcher);
            $this->fail("Discovery should have failed.");
        } catch (GApps_Discovery_Exception $e) {}
    }
}
?>