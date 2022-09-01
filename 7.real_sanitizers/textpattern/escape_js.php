<?php
/**
 * Sanitises a string for use in a JavaScript string.
 *
 * Escapes \, \n, \r, " and ' characters. It removes 'PARAGRAPH SEPARATOR'
 * (U+2029) and 'LINE SEPARATOR' (U+2028). When you need to pass a string
 * from PHP to JavaScript, use this function to sanitise the value to avoid
 * XSS attempts.
 *
 * @param   string $js JavaScript input
 * @return  string Escaped JavaScript
 * @since   4.4.0
 * @package Filter
 */

function escape_js($js)
{
    $js = preg_replace('/[\x{2028}\x{2029}]/u', '', $js);

    return addcslashes($js, "\\\'\"\n\r");
}
?>