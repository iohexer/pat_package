<?php
class Arr extends AbstractRenderer
{
    /**
     * Make a string containing HTML safe for output on a page.
     *
     * @param string $string The string.
     * @return string The string with the HTML characters replaced by entities.
     */
    private function htmlSafe($string)
    {
        return htmlspecialchars($string, ENT_NOQUOTES, 'UTF-8');
    }
}