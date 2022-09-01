<?php

class HTML {

/**
 * Parse a user submited value
 *
 * @param string $string The string to parse and output
 * @param array $translate An array containing the characters to parse
 * @return string
 * @since v3.0.0
 */
public static function output($string, $translate = null) {
    if ( !isset($translate) ) {
      $translate = array('"' => '&quot;');
    }

    return strtr(trim($string), $translate);
  }
}
?>