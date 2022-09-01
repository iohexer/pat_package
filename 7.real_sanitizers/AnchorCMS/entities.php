<?php
class html {
    public static $encoding;

    /**
     * Encodes HTML entities
     *
     * @param string $value string to encode HTML entities in
     *
     * @return string
     */
    public static function entities($value)
    {
        return htmlentities($value, ENT_QUOTES, static::encoding(), false);
    }
}