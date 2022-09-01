<?php
class StringType implements TypeInterface
{
/**
     * HTML encodes the string.
     *
     * <code>
     * echo (string) Txp::get('\Textpattern\Type\StringType', '<strong>Hello World!</strong>')->html();
     * </code>
     *
     * @param  int  $flags         A bitmask of one or more flags. The default is ENT_QUOTES
     * @param  bool $double_encode When double_encode is turned off PHP will not encode existing HTML entities, the default is to convert everything
     * @return StringType
     */

    public function html($flags = ENT_QUOTES, $double_encode = true)
    {
        $this->string = htmlspecialchars($this->string, $flags, $this->encoding, $double_encode);

        return $this;
    }
}
?>