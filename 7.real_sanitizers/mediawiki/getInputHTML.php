<?php
class HTMLInfoField extends HTMLFormField {
	/**
	 * @inheritDoc
	 * @stable to override
	 */
	public function getInputHTML( $value ) {
		return !empty( $this->mParams['raw'] ) ? $value : htmlspecialchars( $value );
	}
}
?>