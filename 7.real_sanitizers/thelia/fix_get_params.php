<?php
/**
* Cleanup input
*
* @param  string  $str
*
* @return  string
*/
function fix_get_params($str)
{
	return strip_tags(preg_replace("/[^a-zA-Z0-9\.\[\]_| -]/", '', $str));
}
?>