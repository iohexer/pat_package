<?php
class modX extends xPDO {    /**
     * Sanitizes a string
     *
     * @param string $str The string to sanitize
     * @param array $chars An array of chars to remove
     * @param string $allowedTags A list of tags to allow.
     * @return string The sanitized string.
     */
    public function sanitizeString($str,$chars = array('/',"'",'"','(',')',';','>','<'),$allowedTags = '') {
        $str = str_replace($chars,'',strip_tags($str,$allowedTags));
        return preg_replace("/[^A-Za-z0-9_\-\.\/\\p{L}[\p{L} _.-]/u",'',$str);
    }
}
?>