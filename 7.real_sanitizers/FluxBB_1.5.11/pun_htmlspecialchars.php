<?php
//
// Calls htmlspecialchars with a few options already set
//
function pun_htmlspecialchars($str)
{
	return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}
?>