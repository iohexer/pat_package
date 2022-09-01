<?php
/**
 * Retrieve the translation of $text and escapes it for safe use in an attribute.
 *
 * If there is no translation, or the text domain isn't loaded, the original text is returned.
 *
 * @since 2.8.0
 *
 * @param string $text   Text to translate.
 * @param string $domain Optional. Text domain. Unique identifier for retrieving translated strings.
 *                       Default 'default'.
 * @return string Translated text on success, original text on failure.
 */
function esc_attr__( $text, $domain = 'default' ) {
	return esc_attr( translate( $text, $domain ) );
}
?>