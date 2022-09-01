<?php
abstract class AbstractExtension implements \IteratorAggregate, \Countable, \ArrayAccess, RuntimeExtensionInterface
{
    /**
     * Escape a string
     *
     * @param  string $string
     *
     * @return string
     */
    protected function _escape($string)
    {
        return htmlspecialchars((string) $string);
    }
}
?>