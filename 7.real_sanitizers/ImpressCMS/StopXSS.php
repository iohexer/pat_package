<?php
/**
 * Searches text for unwanted tags and removes them
 *
 * @param string $text	String to purify
 * @return string	$text The purified text
 * @todo Remove and replace with the proper data filter and HTML Purifier
 */
function StopXSS($text)
{
	if(!is_array($text))
	{
		$text = preg_replace("/\(\)/si", "", $text);
		$text = strip_tags($text);
		$text = str_replace(array("\"",">","<","\\"), "", $text);
	}
	else
	{
		foreach($text as $k=>$t)
		{
			if (is_array($t)) {
				StopXSS($t);
			} else {
				$t = preg_replace("/\(\)/si", "", $t);
				$t = strip_tags($t);
				$t = str_replace(array("\"",">","<","\\"), "", $t);
				$text[$k] = $t;
			}
		}
	}
	return $text;
}
?>