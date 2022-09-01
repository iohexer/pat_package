<?php
	/**
		* procedure dynpg_htmlentities()
		*
		*
		*
		* @package DynPG Engine
		* @author Daniel Schliebner <mail@ds-develop.de>
		* @version 1.0
		* @access public
		* @copyright Daniel Schliebner, 08.01.2007
		* @param string: string
		* @return string
		*/
        function dynpg_htmlentities($string) {
            $_offset = $string;
            $_encoding = 'UTF-8';
            //convert from utf8 to htmlentities for utf8 charset mysql databases
            if(function_exists('mb_convert_encoding') && function_exists('mb_detect_encoding') && mb_detect_encoding($_offset.'a', "ISO-8859-1, UTF-8, ASCII") == 'ISO-8859-1'){
              $_offset = trim(mb_convert_encoding($_offset, 'HTML-ENTITIES', 'UTF-8'), "\x00..\x1F");
              $_encoding = 'ISO-8859-1';
            }
            $secure_replace = time();
            $_offset = str_replace("<", "#".$secure_replace."#lt", $_offset);
            $_offset = str_replace(">", "#".$secure_replace."#gt", $_offset);
            $_offset = str_replace("&", "#".$secure_replace."#amp", $_offset);
            $_offset = htmlentities($_offset, ENT_NOQUOTES, $_encoding);
            $_offset = str_replace("#".$secure_replace."#lt", "<", $_offset);
            $_offset = str_replace("#".$secure_replace."#gt", ">", $_offset);
            $_offset = str_replace("#".$secure_replace."#amp", "&", $_offset);
    
            return $_offset;
        }
?>