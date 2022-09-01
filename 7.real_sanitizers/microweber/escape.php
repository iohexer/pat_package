<?php
abstract class Element
{
protected function escape($value)
{
    return htmlentities($value, ENT_QUOTES, 'UTF-8');
}
}
?>