<?php
/**
 * Filters text content and strips out disallowed HTML.
 *
 * This function makes sure that only the allowed HTML element names, attribute
 * names, attribute values, and HTML entities will occur in the given text string.
 *
 * This function expects unslashed data.
 *
 * @see wp_kses_post() for specifically filtering post content and fields.
 * @see wp_allowed_protocols() for the default allowed protocols in link URLs.
 *
 * @since 1.0.0
 *
 * @param string         $string            Text content to filter.
 * @param array[]|string $allowed_html      An array of allowed HTML elements and attributes,
 *                                          or a context name such as 'post'. See wp_kses_allowed_html()
 *                                          for the list of accepted context names.
 * @param string[]       $allowed_protocols Array of allowed URL protocols.
 * @return string Filtered content containing only the allowed HTML.
 */
function wp_kses( $string, $allowed_html, $allowed_protocols = array() ) {
	if ( empty( $allowed_protocols ) ) {
		$allowed_protocols = wp_allowed_protocols();
	}

	$string = wp_kses_no_null( $string, array( 'slash_zero' => 'keep' ) );
	$string = wp_kses_normalize_entities( $string );
	$string = wp_kses_hook( $string, $allowed_html, $allowed_protocols );

	return wp_kses_split( $string, $allowed_html, $allowed_protocols );
}
?>