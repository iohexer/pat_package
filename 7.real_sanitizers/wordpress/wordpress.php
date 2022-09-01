<?php
/**
 * Checks and cleans a URL.
 *
 * A number of characters are removed from the URL. If the URL is for displaying
 * (the default behaviour) ampersands are also replaced. The {@see 'clean_url'} filter
 * is applied to the returned cleaned URL.
 *
 * @since 2.8.0
 *
 * @param string   $url       The URL to be cleaned.
 * @param string[] $protocols Optional. An array of acceptable protocols.
 *                            Defaults to return value of wp_allowed_protocols().
 * @param string   $_context  Private. Use esc_url_raw() for database usage.
 * @return string The cleaned URL after the {@see 'clean_url'} filter is applied.
 */
function esc_url( $url, $protocols = null, $_context = 'display' ) {
	$original_url = $url;

	if ( '' === $url ) {
		return $url;
	}

	$url = str_replace( ' ', '%20', ltrim( $url ) );
	$url = preg_replace( '|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\[\]\\x80-\\xff]|i', '', $url );

	if ( '' === $url ) {
		return $url;
	}

	if ( 0 !== stripos( $url, 'mailto:' ) ) {
		$strip = array( '%0d', '%0a', '%0D', '%0A' );
		$url   = _deep_replace( $strip, $url );
	}

	$url = str_replace( ';//', '://', $url );
	/*
	 * If the URL doesn't appear to contain a scheme, we presume
	 * it needs http:// prepended (unless it's a relative link
	 * starting with /, # or ?, or a PHP file).
	 */
	if ( strpos( $url, ':' ) === false && ! in_array( $url[0], array( '/', '#', '?' ), true ) &&
		! preg_match( '/^[a-z0-9-]+?\.php/i', $url ) ) {
		$url = 'http://' . $url;
	}

	// Replace ampersands and single quotes only when displaying.
	if ( 'display' === $_context ) {
		$url = wp_kses_normalize_entities( $url );
		$url = str_replace( '&amp;', '&#038;', $url );
		$url = str_replace( "'", '&#039;', $url );
	}

	if ( ( false !== strpos( $url, '[' ) ) || ( false !== strpos( $url, ']' ) ) ) {

		$parsed = wp_parse_url( $url );
		$front  = '';

		if ( isset( $parsed['scheme'] ) ) {
			$front .= $parsed['scheme'] . '://';
		} elseif ( '/' === $url[0] ) {
			$front .= '//';
		}

		if ( isset( $parsed['user'] ) ) {
			$front .= $parsed['user'];
		}

		if ( isset( $parsed['pass'] ) ) {
			$front .= ':' . $parsed['pass'];
		}

		if ( isset( $parsed['user'] ) || isset( $parsed['pass'] ) ) {
			$front .= '@';
		}

		if ( isset( $parsed['host'] ) ) {
			$front .= $parsed['host'];
		}

		if ( isset( $parsed['port'] ) ) {
			$front .= ':' . $parsed['port'];
		}

		$end_dirty = str_replace( $front, '', $url );
		$end_clean = str_replace( array( '[', ']' ), array( '%5B', '%5D' ), $end_dirty );
		$url       = str_replace( $end_dirty, $end_clean, $url );

	}

	if ( '/' === $url[0] ) {
		$good_protocol_url = $url;
	} else {
		if ( ! is_array( $protocols ) ) {
			$protocols = wp_allowed_protocols();
		}
		$good_protocol_url = wp_kses_bad_protocol( $url, $protocols );
		if ( strtolower( $good_protocol_url ) != strtolower( $url ) ) {
			return '';
		}
	}

	/**
	 * Filters a string cleaned and escaped for output as a URL.
	 *
	 * @since 2.3.0
	 *
	 * @param string $good_protocol_url The cleaned URL to be returned.
	 * @param string $original_url      The URL prior to cleaning.
	 * @param string $_context          If 'display', replace ampersands and single quotes only.
	 */
	return apply_filters( 'clean_url', $good_protocol_url, $original_url, $_context );
}

/*
 * Convert entities, while preserving already-encoded entities.
 *
 * @link https://www.php.net/htmlentities Borrowed from the PHP Manual user notes.
 *
 * @since 1.2.2
 *
 * @param string $myHTML The text to be converted.
 * @return string Converted text.
 */
function htmlentities2( $myHTML ) {
	$translation_table              = get_html_translation_table( HTML_ENTITIES, ENT_QUOTES );
	$translation_table[ chr( 38 ) ] = '&';
	return preg_replace( '/&(?![A-Za-z]{0,4}\w{2,3};|#[0-9]{2,3};)/', '&amp;', strtr( $myHTML, $translation_table ) );
}

/**
 * Escaping for textarea values.
 *
 * @since 3.1.0
 *
 * @param string $text
 * @return string
 */
function esc_textarea( $text ) {
	$safe_text = htmlspecialchars( $text, ENT_QUOTES, get_option( 'blog_charset' ) );
	/**
	 * Filters a string cleaned and escaped for output in a textarea element.
	 *
	 * @since 3.1.0
	 *
	 * @param string $safe_text The text after it has been escaped.
	 * @param string $text      The text prior to being escaped.
	 */
	return apply_filters( 'esc_textarea', $safe_text, $text );
}

/**
 * Escaping for XML blocks.
 *
 * @since 5.5.0
 *
 * @param string $text Text to escape.
 * @return string Escaped text.
 */
function esc_xml( $text ) {
	$safe_text = wp_check_invalid_utf8( $text );

	$cdata_regex = '\<\!\[CDATA\[.*?\]\]\>';
	$regex       = <<<EOF
/
	(?=.*?{$cdata_regex})                 # lookahead that will match anything followed by a CDATA Section
	(?<non_cdata_followed_by_cdata>(.*?)) # the "anything" matched by the lookahead
	(?<cdata>({$cdata_regex}))            # the CDATA Section matched by the lookahead

|	                                      # alternative

	(?<non_cdata>(.*))                    # non-CDATA Section
/sx
EOF;

	$safe_text = (string) preg_replace_callback(
		$regex,
		static function( $matches ) {
			if ( ! $matches[0] ) {
				return '';
			}

			if ( ! empty( $matches['non_cdata'] ) ) {
				// escape HTML entities in the non-CDATA Section.
				return _wp_specialchars( $matches['non_cdata'], ENT_XML1 );
			}

			// Return the CDATA Section unchanged, escape HTML entities in the rest.
			return _wp_specialchars( $matches['non_cdata_followed_by_cdata'], ENT_XML1 ) . $matches['cdata'];
		},
		$safe_text
	);

	/**
	 * Filters a string cleaned and escaped for output in XML.
	 *
	 * Text passed to esc_xml() is stripped of invalid or special characters
	 * before output. HTML named character references are converted to their
	 * equivalent code points.
	 *
	 * @since 5.5.0
	 *
	 * @param string $safe_text The text after it has been escaped.
	 * @param string $text      The text prior to being escaped.
	 */
	return apply_filters( 'esc_xml', $safe_text, $text );
}

/**
 * Escape an HTML tag name.
 *
 * @since 2.5.0
 *
 * @param string $tag_name
 * @return string
 */
function tag_escape( $tag_name ) {
	$safe_tag = strtolower( preg_replace( '/[^a-zA-Z0-9_:]/', '', $tag_name ) );
	/**
	 * Filters a string cleaned and escaped for output as an HTML tag.
	 *
	 * @since 2.8.0
	 *
	 * @param string $safe_tag The tag name after it has been escaped.
	 * @param string $tag_name The text before it was escaped.
	 */
	return apply_filters( 'tag_escape', $safe_tag, $tag_name );
}

/**
 * Properly strip all HTML tags including script and style
 *
 * This differs from strip_tags() because it removes the contents of
 * the `<script>` and `<style>` tags. E.g. `strip_tags( '<script>something</script>' )`
 * will return 'something'. wp_strip_all_tags will return ''
 *
 * @since 2.9.0
 *
 * @param string $string        String containing HTML tags
 * @param bool   $remove_breaks Optional. Whether to remove left over line breaks and white space chars
 * @return string The processed string.
 */
function wp_strip_all_tags( $string, $remove_breaks = false ) {
	$string = preg_replace( '@<(script|style)[^>]*?>.*?</\\1>@si', '', $string );
	$string = strip_tags( $string );

	if ( $remove_breaks ) {
		$string = preg_replace( '/[\r\n\t ]+/', ' ', $string );
	}

	return trim( $string );
}


/**
 * Sanitizes a string from user input or from the database.
 *
 * - Checks for invalid UTF-8,
 * - Converts single `<` characters to entities
 * - Strips all tags
 * - Removes line breaks, tabs, and extra whitespace
 * - Strips octets
 *
 * @since 2.9.0
 *
 * @see sanitize_textarea_field()
 * @see wp_check_invalid_utf8()
 * @see wp_strip_all_tags()
 *
 * @param string $str String to sanitize.
 * @return string Sanitized string.
 */
function sanitize_text_field( $str ) {
	$filtered = _sanitize_text_fields( $str, false );

	/**
	 * Filters a sanitized text field string.
	 *
	 * @since 2.9.0
	 *
	 * @param string $filtered The sanitized string.
	 * @param string $str      The string prior to being sanitized.
	 */
	return apply_filters( 'sanitize_text_field', $filtered, $str );
}

/**
 * Sanitizes a multiline string from user input or from the database.
 *
 * The function is like sanitize_text_field(), but preserves
 * new lines (\n) and other whitespace, which are legitimate
 * input in textarea elements.
 *
 * @see sanitize_text_field()
 *
 * @since 4.7.0
 *
 * @param string $str String to sanitize.
 * @return string Sanitized string.
 */
function sanitize_textarea_field( $str ) {
	$filtered = _sanitize_text_fields( $str, true );

	/**
	 * Filters a sanitized textarea field string.
	 *
	 * @since 4.7.0
	 *
	 * @param string $filtered The sanitized string.
	 * @param string $str      The string prior to being sanitized.
	 */
	return apply_filters( 'sanitize_textarea_field', $filtered, $str );
}

/**
 * Internal helper function to sanitize a string from user input or from the db
 *
 * @since 4.7.0
 * @access private
 *
 * @param string $str           String to sanitize.
 * @param bool   $keep_newlines Optional. Whether to keep newlines. Default: false.
 * @return string Sanitized string.
 */
function _sanitize_text_fields( $str, $keep_newlines = false ) {
	if ( is_object( $str ) || is_array( $str ) ) {
		return '';
	}

	$str = (string) $str;

	$filtered = wp_check_invalid_utf8( $str );

	if ( strpos( $filtered, '<' ) !== false ) {
		$filtered = wp_pre_kses_less_than( $filtered );
		// This will strip extra whitespace for us.
		$filtered = wp_strip_all_tags( $filtered, false );

		// Use HTML entities in a special case to make sure no later
		// newline stripping stage could lead to a functional tag.
		$filtered = str_replace( "<\n", "&lt;\n", $filtered );
	}

	if ( ! $keep_newlines ) {
		$filtered = preg_replace( '/[\r\n\t ]+/', ' ', $filtered );
	}
	$filtered = trim( $filtered );

	$found = false;
	while ( preg_match( '/%[a-f0-9]{2}/i', $filtered, $match ) ) {
		$filtered = str_replace( $match[0], '', $filtered );
		$found    = true;
	}

	if ( $found ) {
		// Strip out the whitespace that may now exist after removing the octets.
		$filtered = trim( preg_replace( '/ +/', ' ', $filtered ) );
	}

	return $filtered;
}
