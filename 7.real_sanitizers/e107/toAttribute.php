<?php
/**
 * Use it on html attributes to avoid breaking markup .
 * @example echo "<a href='#' title='".$tp->toAttribute($text)."'>Hello</a>";
 */
function toAttribute($text)
{
	// URLs posted without HTML access may have an &amp; in them.

	// Xhtml compliance.
	$text = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');

	if(!preg_match('/&#|\'|"|<|>/s', $text))
	{
		$text = $this->replaceConstants($text);
		return $text;
	}
	else
	{
		return $text;
	}
}
?>