<?php
class FeedItem {
	/**
	 * Encode $string so that it can be safely embedded in a XML document
	 *
	 * @param string $string String to encode
	 * @return string
	 */
	public function xmlEncode( $string ) {
		$string = str_replace( "\r\n", "\n", $string );
		$string = preg_replace( '/[\x00-\x08\x0b\x0c\x0e-\x1f]/', '', $string );
		return htmlspecialchars( $string );
	}
}
?>