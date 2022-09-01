<?php
/**
 * @psalm-immutable
 */
final class UTF8
{
    /**
     * Remove html via "strip_tags()" from the string.
     *
     * @param string $str            <p>The input string.</p>
     * @param string $allowable_tags [optional] <p>You can use the optional second parameter to specify tags which
     *                               should not be stripped. Default: null
     *                               </p>
     *
     * @psalm-pure
     *
     * @return string
     *                <p>A string with without html tags.</p>
     */
    public static function remove_html(string $str, string $allowable_tags = ''): string
    {
        return \strip_tags($str, $allowable_tags);
    }
}
?>