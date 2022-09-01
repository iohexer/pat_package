<?php
	function dhtmlspecialchars($string, $flags = null) {
		if(is_array($string)) {
			foreach($string as $key => $val) {
				$string[$key] = dhtmlspecialchars($val, $flags);
			}
		} else {
			if($flags === null) {
				$string = str_replace(array('&', '"', '<', '>'), array('&amp;', '&quot;', '&lt;', '&gt;'), $string);
				if(strpos($string, '&amp;#') !== false) {
					$string = preg_replace('/&amp;((#(\d{3,5}|x[a-fA-F0-9]{4}));)/', '&\\1', $string);
				}
			} else {
				if(PHP_VERSION < '5.4.0') {
					$string = htmlspecialchars($string, $flags);
				} else {
					if(strtolower(CHARSET) == 'utf-8') {
						$charset = 'UTF-8';
					} else {
						$charset = 'ISO-8859-1';
					}
					$string = htmlspecialchars($string, $flags, $charset);
				}
			}
		}
		return $string;
	}
?>