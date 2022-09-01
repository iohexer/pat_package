<?php
/**
 * Sanitizes an HTML classname to ensure it only contains valid characters.
 *
 * Strips the string down to A-Z,a-z,0-9,_,-. If this results in an empty
 * string then it will return the alternative value supplied.
 *
 * @todo Expand to support the full range of CDATA that a class attribute can contain.
 *
 * @since 2.8.0
 *
 * @param string $class    The classname to be sanitized
 * @param string $fallback Optional. The value to return if the sanitization ends up as an empty string.
 *  Defaults to an empty string.
 * @return string The sanitized value
 */
function sanitize_html_class( $class, $fallback = '' ) {
	// Strip out any %-encoded octets.
	$sanitized = preg_replace( '|%[a-fA-F0-9][a-fA-F0-9]|', '', $class );

	// Limit to A-Z, a-z, 0-9, '_', '-'.
	$sanitized = preg_replace( '/[^A-Za-z0-9_-]/', '', $sanitized );

	if ( '' === $sanitized && $fallback ) {
		return sanitize_html_class( $fallback );
	}
	/**
	 * Filters a sanitized HTML class string.
	 *
	 * @since 2.8.0
	 *
	 * @param string $sanitized The sanitized HTML class.
	 * @param string $class     HTML class before sanitization.
	 * @param string $fallback  The fallback string.
	 */
	return apply_filters( 'sanitize_html_class', $sanitized, $class, $fallback );
}
?>