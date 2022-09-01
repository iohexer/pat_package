<?php
//
// Common helpers and forum's wrappers for PHP functions
//

// Encodes the contents of $str so that they are safe to output on an (X)HTML page
function forum_htmlencode($str)
{
	return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}
