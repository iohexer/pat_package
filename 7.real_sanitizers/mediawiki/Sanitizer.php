<?php

/**
 * HTML sanitizer for MediaWiki
 * @ingroup Parser
 */
class Sanitizer {

/**
 * Encode an attribute value for HTML output.
 * @param string $text
 * @return string HTML-encoded text fragment
 */
public static function encodeAttribute( $text ) {
	$encValue = htmlspecialchars( $text, ENT_QUOTES );

        // Whitespace is normalized during attribute decoding,
	// so if we've been passed non-spaces we must encode them
	// ahead of time or they won't be preserved.
	$encValue = strtr( $encValue, [
		"\n" => '&#10;',
		"\r" => '&#13;',
		"\t" => '&#9;',
	] );

	return $encValue;
}

/**
 * Build a partial tag string from an associative array of attribute
 * names and values as returned by decodeTagAttributes.
 *
 * @param array $assoc_array
 * @return string
 */
public static function safeEncodeTagAttributes( $assoc_array ) {
	$attribs = [];
	foreach ( $assoc_array as $attribute => $value ) {
		$encAttribute = htmlspecialchars( $attribute );
		$encValue = self::safeEncodeAttribute( $value );

		$attribs[] = "$encAttribute=\"$encValue\"";
	}
	return count( $attribs ) ? ' ' . implode( ' ', $attribs ) : '';
}



/**
 * Given HTML input, escape with htmlspecialchars but un-escape entities.
 * This allows (generally harmless) entities like &#160; to survive.
 *
 * @param string $html HTML to escape
 * @return string Escaped input
 */
public static function escapeHtmlAllowEntities( $html ) {
	$html = self::decodeCharReferences( $html );
	# It seems wise to escape ' as well as ", as a matter of course.  Can't
	# hurt. Use ENT_SUBSTITUTE so that incorrectly truncated multibyte characters
	# don't cause the entire string to disappear.
	$html = htmlspecialchars( $html, ENT_QUOTES | ENT_SUBSTITUTE );
	return $html;
}

}