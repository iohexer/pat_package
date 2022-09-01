<?php
//mediawiki-master//tests/phpunit/includes/logging/LogFormatterTestCase.php
abstract class LogFormatterTestCase extends MediaWikiLangTestCase {
private static function removeSomeHtml( $html ) {
		$html = str_replace( '&quot;', '"', $html );
		$html = preg_replace( '/\xE2\x80[\x8E\x8F]/', '', $html ); // Strip lrm/rlm
		return trim( strip_tags( $html ) );
	}
}
?>