<?php
class MantisCoreFormattingPlugin extends MantisFormattingPlugin {
	/**
	 * Process Text, make sure to block any possible xss attacks
	 *
	 * @param string  $p_string    Raw text to process.
	 * @param boolean $p_multiline True for multiline text (default), false for single-line.
	 *                             Determines which html tags are used.
	 *
	 * @return string valid formatted text
	 */
	private function processText( $p_string, $p_multiline = true ){

		$t_string = string_strip_hrefs( $p_string );
		$t_string = string_html_specialchars( $t_string );
		return string_restore_valid_html_tags( $t_string, $p_multiline );
	}
}
?>