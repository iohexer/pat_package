<?php
namespace MicroweberPackages\Helper;


/**
 * This is the security class.
 *
 * Some code in this class it taken from CodeIgniter 3.
 * See the original here: http://bit.ly/1oQnpjn.
 *
 * @author Andrey Andreev <narf@bofh.bg>
 * @author Derek Jones <derek.jones@ellislab.com>
 * @author Graham Campbell <graham@cachethq.io>
 */
class XSSSecurity
{
    /**
     * Compact exploded words.
     *
     * @param array $matches
     *
     * @return string
     */
    protected function compactExplodedWords($matches)
    {
        return preg_replace('/\s+/s', '', $matches[1]).$matches[2];
    }

    /**
     * Remove evil html attributes.
     *
     * @param string $str
     *
     * @return string
     */
    public function removeEvilAttributes($str)
    {
        do {
            $count = $tempCount = 0;

            // replace occurrences of illegal attribute strings with quotes (042 and 047 are octal quotes)
            $str = preg_replace('/(<[^>]+)(?<!\w)('.implode('|', $this->evil).')\s*=\s*(\042|\047)([^\\2]*?)(\\2)/is', '$1[removed]', $str, -1, $tempCount);
            $count += $tempCount;

            // find occurrences of illegal attribute strings without quotes
            $str = preg_replace('/(<[^>]+)(?<!\w)('.implode('|', $this->evil).')\s*=\s*([^\s>]*)/is', '$1[removed]', $str, -1, $tempCount);
            $count += $tempCount;
        } while ($count);

        return $str;
    }

    /**
     * Sanitize naughty html.
     *
     * @param array $matches
     *
     * @return string
     */
    protected function sanitizeNaughtyHtml($matches)
    {
        return '&lt;'.$matches[1].$matches[2].$matches[3]
            .str_replace(['>', '<'], ['&gt;', '&lt;'], $matches[4]);
    }

    /**
     * JS link removal.
     *
     * @param array $match
     *
     * @return string
     */
    protected function jsLinkRemoval($match)
    {
        return str_replace(
            $match[1],
            preg_replace(
                '#href=.*?(?:(?:alert|prompt|confirm)(?:\(|&\#40;)|javascript:|livescript:|mocha:|charset=|window\.|document\.|\.cookie|<script|<xss|data\s*:)#si',
                '',
                $this->filterAttributes(str_replace(['<', '>'], '', $match[1]))
            ),
            $match[0]
        );
    }

    /**
     * JS image removal.
     *
     * @param array $match
     *
     * @return string
     */
    protected function jsImgRemoval($match)
    {
        return str_replace(
            $match[1],
            preg_replace(
                '#src=.*?(?:(?:alert|prompt|confirm)(?:\(|&\#40;)|javascript:|livescript:|mocha:|charset=|window\.|document\.|\.cookie|<script|<xss|base64\s*,)#si',
                '',
                $this->filterAttributes(str_replace(['<', '>'], '', $match[1]))
            ),
            $match[0]
        );
    }

    /**
     * Attribute conversion.
     *
     * @param array $match
     *
     * @return string
     */
    protected function convertAttribute($match)
    {
        return str_replace(['>', '<', '\\'], ['&gt;', '&lt;', '\\\\'], $match[0]);
    }

    /**
     * Attribute filtering.
     *
     * @param string $str
     *
     * @return string
     */
    protected function filterAttributes($str)
    {
        $out = '';

        if (preg_match_all('#\s*[a-z\-]+\s*=\s*(\042|\047)([^\\1]*?)\\1#is', $str, $matches)) {
            foreach ($matches[0] as $match) {
                $out .= preg_replace('#/\*.*?\*/#s', '', $match);
            }
        }

        return $out;
    }

    /**
     * HTML entity decode callback.
     *
     * @param array $match
     *
     * @return string
     */
    protected function decodeEntity($match)
    {
        $hash = $this->xssHash();

        $match = preg_replace('|\&([a-z\_0-9\-]+)\=([a-z\_0-9\-/]+)|i', $hash.'\\1=\\2', $match[0]);

        return str_replace($hash, '&', $this->entityDecode($match));
    }

    /**
     * Do never allowed.
     *
     * @param string $str
     *
     * @return string
     */
    protected function doNeverAllowed($str)
    {
        $never = [
            'document.cookie' => '[removed]',
            'document.write' => '[removed]',
            '.parentNode' => '[removed]',
            '.innerHTML' => '[removed]',
            '-moz-binding' => '[removed]',
            '<!--' => '&lt;!--',
            '-->' => '--&gt;',
            '<![CDATA[' => '&lt;![CDATA[',
            '<comment>' => '&lt;comment&gt;',
        ];

        $str = str_replace(array_keys($never), $never, $str);

        $regex = [
            'javascript\s*:',
            '(document|(document\.)?window)\.(location|on\w*)',
            'expression\s*(\(|&\#40;)',
            'vbscript\s*:',
            'wscript\s*:',
            'jscript\s*:',
            'vbs\s*:',
            'Redirect\s+30\d',
            "([\"'])?data\s*:[^\\1]*?base64[^\\1]*?,[^\\1]*?\\1?",
        ];

        foreach ($regex as $val) {
            $str = preg_replace('#'.$val.'#is', '[removed]', $str);
        }

        return $str;
    }
}
