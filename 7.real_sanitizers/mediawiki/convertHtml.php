<?php
class TrivialLanguageConverter implements ILanguageConverter { 
	/**
	 * Perform output conversion on a string, and encode for safe HTML output.
	 *
	 * @since 1.35
	 *
	 * @param string $text Text to be converted
	 * @return string
	 */
	public function convertHtml( $text ) {
		return htmlspecialchars( $this->convert( $text ) );
	}
}
}
?>