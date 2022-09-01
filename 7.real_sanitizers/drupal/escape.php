<?php
 /**
   * Escapes text by converting special characters to HTML entities.
   *
   * This method escapes HTML for sanitization purposes by replacing the
   * following special characters with their HTML entity equivalents:
   * - & (ampersand) becomes &amp;
   * - " (double quote) becomes &quot;
   * - ' (single quote) becomes &#039;
   * - < (less than) becomes &lt;
   * - > (greater than) becomes &gt;
   * Special characters that have already been escaped will be double-escaped
   * (for example, "&lt;" becomes "&amp;lt;"), and invalid UTF-8 encoding
   * will be converted to the Unicode replacement character ("�").
   *
   * This method is not the opposite of Html::decodeEntities(). For example,
   * this method will not encode "é" to "&eacute;", whereas
   * Html::decodeEntities() will convert all HTML entities to UTF-8 bytes,
   * including "&eacute;" and "&lt;" to "é" and "<".
   *
   * When constructing @link theme_render render arrays @endlink passing the output of Html::escape() to
   * '#markup' is not recommended. Use the '#plain_text' key instead and the
   * renderer will autoescape the text.
   *
   * @param string $text
   *   The input text.
   *
   * @return string
   *   The text with all HTML special characters converted.
   *
   * @see htmlspecialchars()
   * @see \Drupal\Component\Utility\Html::decodeEntities()
   *
   * @ingroup sanitization
   */
  function escape($text) {
    return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
  }