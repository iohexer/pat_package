<?php
/**
 * Calls htmlentities on the specified string, passing along
 * the current character set.
 * @param string $p_string The string to process.
 * @return string
 */
function string_html_entities( $p_string ) {
	return htmlentities( $p_string, ENT_COMPAT, 'utf-8' );
}
?>