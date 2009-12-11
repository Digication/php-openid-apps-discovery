<?php

class GApps_Test_Fixtures {
    
    static function read_file($name) {
        $file = dirname(__FILE__).'/fixtures/'.$name;
        $handle = fopen($file, "r");
        $contents = fread($handle, filesize($file));   
        fclose($handle);        
        return $contents;
    }
}
?>
