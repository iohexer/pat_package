<?php
/**
 * Performs esc_url() for database usage.
 *
 * @since 2.8.0
 *
 * @see esc_url()
 *
 * @param string   $url       The URL to be cleaned.
 * @param string[] $protocols Optional. An array of acceptable protocols.
 *                            Defaults to return value of wp_allowed_protocols().
 * @return string The cleaned URL after esc_url() is run with the 'db' context.
 */
function esc_url_raw( $url, $protocols = null ) {
	return esc_url( $url, $protocols, 'db' );
}
?>