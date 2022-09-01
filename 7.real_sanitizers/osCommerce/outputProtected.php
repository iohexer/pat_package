<?php

class HTML {
/**
 * Strictly parse a user submited value
 *
 * @param string $string The string to strictly parse and output
 * @return string
 * @since v3.0.0
 */

public static function outputProtected($string) {
  return htmlspecialchars(trim($string));
}
}
?>