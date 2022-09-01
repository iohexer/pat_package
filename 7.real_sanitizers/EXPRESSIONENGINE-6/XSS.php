<?php
/**
 * This source file is part of the open source project
 * ExpressionEngine (https://expressionengine.com)
 *
 * @link      https://expressionengine.com/
 * @copyright Copyright (c) 2003-2020, Packet Tide, LLC (https://www.packettide.com)
 * @license   https://expressionengine.com/license Licensed under Apache License, Version 2.0
 */

namespace ExpressionEngine\Library\Security;

/**
 * Security XSS
 */
class XSS
{
    /**
     * Compact Exploded Words
     *
     * Callback function for xss_clean() to remove whitespace from
     * things like j a v a s c r i p t
     *
     * @param	type
     * @return	type
     */
    protected function _compact_exploded_words($matches)
    {
        return preg_replace('/\s+/s', '', $matches[1]) . $matches[2];
    }

    /**
     * Remove Evil HTML Attributes (like evenhandlers and style)
     *
     * It removes the evil attribute and either:
     * 	- Everything up until a space
     *		For example, everything between the pipes:
     *		<a |style=document.write('hello');alert('world');| class=link>
     * 	- Everything inside the quotes
     *		For example, everything between the pipes:
     *		<a |style="document.write('hello'); alert('world');"| class="link">
     *
     * @param string $str The string to check
     * @param boolean $is_image TRUE if this is an image
     * @return string The string with the evil attributes removed
     */
    protected function _remove_evil_attributes($str, $is_image)
    {
        // All javascript event handlers (e.g. onload, onclick, onmouseover), style, and xmlns
        $evil_attributes = array('on\w{2,}', 'style', 'xmlns', 'formaction');

        if ($is_image === true) {
            /*
             * Adobe Photoshop puts XML metadata into JFIF images,
             * including namespacing, so we have to allow this for images.
             */
            unset($evil_attributes[array_search('xmlns', $evil_attributes)]);
        }

        do {
            $count = 0;
            $attribs = array();

            // find occurrences of illegal attribute strings without quotes
            preg_match_all('/(\W' . implode('|', $evil_attributes) . ')\s*=\s*([^\s>]*)/is', $str, $matches, PREG_SET_ORDER);

            foreach ($matches as $attr) {
                $attribs[] = trim(preg_quote($attr[0], '/'));
            }

            // find occurrences of illegal attribute strings with quotes (042 and 047 are octal quotes)
            preg_match_all('/(\W' . implode('|', $evil_attributes) . ')\s*=\s*(\042|\047)([^\\2]*?)(\\2)/is', $str, $matches, PREG_SET_ORDER);

            foreach ($matches as $attr) {
                $attribs[] = trim(preg_quote($attr[0], '/'));
            }

            // replace illegal attribute strings that are inside an html tag
            if (count($attribs) > 0) {
                $str = preg_replace("/<(\/?[^><]+?)([^A-Za-z<>\-])(.*?)(" . implode('|', $attribs) . ")(.*?)([\s><]*)([><]*)/i", '<$1 $3$5$6$7', $str, -1, $count);
            }
        } while ($count);

        return $str;
    }

    /**
     * Sanitize Naughty HTML
     *
     * Callback function for xss_clean() to remove naughty HTML elements
     *
     * @param	array
     * @return	string
     */
    protected function _sanitize_naughty_html($matches)
    {
        // encode opening brace
        $str = '&lt;' . $matches[1] . $matches[2] . $matches[3];

        // encode captured opening or closing brace to prevent recursive vectors
        $str .= str_replace(
            array('>', '<'),
            array('&gt;', '&lt;'),
            $matches[4]
        );

        return $str;
    }

    /**
     * JS Link Removal
     *
     * Callback function for xss_clean() to sanitize links
     * This limits the PCRE backtracks, making it more performance friendly
     * and prevents PREG_BACKTRACK_LIMIT_ERROR from being triggered in
     * PHP 5.2+ on link-heavy strings
     *
     * @param	array
     * @return	string
     */
    protected function _js_link_removal($match)
    {
        $attributes = $this->_filter_attributes(str_replace(array('<', '>'), '', $match[1]));

        return str_replace($match[1], preg_replace("#href=.*?(alert\(|alert&\#40;|javascript\:|livescript\:|mocha\:|charset\=|window\.|document\.|\.cookie|<script|<xss|data\s*:)#si", "", $attributes), $match[0]);
    }

    /**
     * JS Image Removal
     *
     * Callback function for xss_clean() to sanitize image tags
     * This limits the PCRE backtracks, making it more performance friendly
     * and prevents PREG_BACKTRACK_LIMIT_ERROR from being triggered in
     * PHP 5.2+ on image tag heavy strings
     *
     * @param	array
     * @return	string
     */
    protected function _js_img_removal($match)
    {
        $attributes = $this->_filter_attributes(str_replace(array('<', '>'), '', $match[1]));

        return str_replace($match[1], preg_replace("#src=.*?(alert\(|alert&\#40;|javascript\:|livescript\:|mocha\:|charset\=|window\.|document\.|\.cookie|<script|<xss|base64\s*,)#si", "", $attributes), $match[0]);
    }

    /**
     * Attribute Conversion
     *
     * Used as a callback for XSS Clean
     *
     * @param	array
     * @return	string
     */
    protected function _convert_attribute($match)
    {
        return str_replace(array('>', '<', '\\'), array('&gt;', '&lt;', '\\\\'), $match[0]);
    }

    /**
     * Filter Attributes
     *
     * Filters tag attributes for consistency and safety
     *
     * @param	string
     * @return	string
     */
    protected function _filter_attributes($str)
    {
        $out = '';

        if (preg_match_all('#\s*[a-z\-]+\s*=\s*(\042|\047)([^\\1]*?)\\1#is', $str, $matches)) {
            foreach ($matches[0] as $match) {
                $out .= preg_replace("#/\*.*?\*/#s", '', $match);
            }
        }

        return $out;
    }


    /**
     * Validate URL entities
     *
     * Called by xss_clean()
     *
     * @param 	string
     * @return 	string
     */
    protected function _validate_entities($str)
    {
        /*
         * Protect GET variables in URLs
         */

        // 901119URL5918AMP18930PROTECT8198

        $str = preg_replace('|\&([a-z\_0-9\-]+)\=([a-z\_0-9\-]+)|i', $this->xss_hash() . "\\1=\\2", $str);

        /*
         * Validate standard character entities
         *
         * Add a semicolon if missing.  We do this to enable
         * the conversion of entities to ASCII later.
         *
         */
        $str = preg_replace('#(&\#?[0-9a-z]{2,})([\x00-\x20])*;?#i', "\\1;\\2", $str);

        /*
         * Validate UTF16 two byte encoding (x00)
         *
         * Just as above, adds a semicolon if missing.
         *
         */
        $str = preg_replace('#(&\#x?)([0-9A-F]+);?#i', "\\1\\2;", $str);

        /*
         * Un-Protect GET variables in URLs
         */
        $str = str_replace($this->xss_hash(), '&', $str);

        return $str;
    }


    /**
     * Strips all data URIs from a string
     *
     * @param string $match  An array of matches from preg_replace_callback.
     * @access protected
     * @return string  The cleaned string.
     */
    protected function _strip_data_URIs($match)
    {
        $pattern = "/('|\")?(?:\s*)?data:[\w\/\-\.]+?;?(?:\w+;)?\w+?,?.*(?:\\1)?(\s)/i";
        $cleaned = $match[0];
        $cleaned = preg_replace($pattern, '$1$1$2', $cleaned);

        return $cleaned;
    }
}

// EOF
