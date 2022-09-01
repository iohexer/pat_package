<?php
/**
 * Prepare a string for display in rss
 * @param string $p_string String to be processed.
 * @return string
 */
function string_rss_links( $p_string ) {
	# rss can not start with &#160; which spaces will be replaced into by string_display().
	$t_string = trim( $p_string );

	$t_string = event_signal( 'EVENT_DISPLAY_RSS', $t_string );

	# another escaping to escape the special characters created by the generated links
	return string_html_specialchars( $t_string );
}
?>