<?php
class HTML {
   /**
     * Escapes special characters
     *
     * @param string $value string to escape
     *
     * @return string
     */
    public static function specialchars($value)
    {
        return htmlspecialchars($value, ENT_QUOTES, static::encoding(), false);
    }

}
    ?>