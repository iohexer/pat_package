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
 *                An empty string is returned if `$url` specifies a protocol other than
 *                those in `$protocols`, or if `$url` contains an empty string.
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
?>