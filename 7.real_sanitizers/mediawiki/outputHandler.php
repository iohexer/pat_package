<?php
abstract class DatabaseInstaller {
	public function outputHandler( $string ) {
		return htmlspecialchars( $string );
	}
}
?>