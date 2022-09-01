<?php
/**
 * Process a string for display in a text box
 * @param string $p_string String to be processed.
 * @return string
 */
function string_attribute( $p_string ) {
	return string_html_specialchars( $p_string );
}
?>