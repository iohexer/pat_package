<?php
/**
 * Calls htmlspecialchars on the specified string, handling utf8
 * @param string $p_string The string to process.
 * @return string
 */
function string_html_specialchars( $p_string ) {
	# achumakov: @ added to avoid warning output in unsupported codepages
	# e.g. 8859-2, windows-1257, Korean, which are treated as 8859-1.
	# This is VERY important for Eastern European, Baltic and Korean languages
	return preg_replace( '/&amp;(#[0-9]+|[a-z]+);/i', '&$1;', @htmlspecialchars( $p_string, ENT_COMPAT, 'utf-8' ) );
}
?>