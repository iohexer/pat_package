<?php
/**
 ***********************************************************************************************
 * @copyright 2004-2022 The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 ***********************************************************************************************
 */
final class SecurityUtils
{
    /**
     * Encodes all HTML special characters
     * If $encodeAll is false, this method is only secure if encoding is not UTF-7
     * @param string $input     The input string
     * @param bool   $encodeAll Set true too encode really all HTML special characters
     * @param string $encoding  Define character encoding to use
     * @return string Encoded string
     */
    public static function encodeHTML($input, $encodeAll = false, $encoding = 'UTF-8')
    {
        if ($encodeAll) {
            // Encodes: all special HTML characters
            return htmlentities($input, ENT_QUOTES | ENT_HTML5, $encoding);
        }

        // Encodes: &, ", ', <, >
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, $encoding);
    }

    /**
     * Build URL with query-string and anker and optional encodes all HTML special characters
     * @param string              $path   The URL path
     * @param array<string,mixed> $params The query-params
     * @param string              $anchor The Url-anker
     * @param bool                $encode Set true to also encode all HTML special characters
     * @return string Encoded URL
     */
    public static function encodeUrl($path, array $params = array(), $anchor = '', $encode = false)
    {
        $paramsText = '';
        if (count($params) > 0) {
            $paramsText = '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
        }

        $anchorText = '';
        if ($anchor !== '') {
            $anchorText = '#' . rawurlencode($anchor);
        }

        $url = $path . $paramsText . $anchorText;

        if ($encode) {
            return self::encodeHTML($url);
        }

        return $url;
    }
}

    ?>