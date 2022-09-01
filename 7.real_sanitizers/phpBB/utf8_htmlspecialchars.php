<?php
/**
* A wrapper for htmlspecialchars($value, ENT_COMPAT, 'UTF-8')
*/
function utf8_htmlspecialchars($value)
{
	return htmlspecialchars($value, ENT_COMPAT, 'UTF-8');
}
?>