<?php

class HTML {
/**
 * Sanitize a user submited value
 *
 * @param string $string The string to sanitize
 * @return string
 * @since v3.0.0
 */

public static function sanitize($string) {
  $patterns = array ('/ +/', '/[<>]/');
  $replace = array (' ', '_');

  return preg_replace($patterns, $replace, trim($string));
}
}

?>