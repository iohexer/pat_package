<?php
/**
 * Get a specific value from an array.
 * Used to fetch user input from POST and GET
 * This sanitizes user input with HTMLPurifier
 *
 * @param array $array The array
 * @param string $name The key we want
 *
 * @return string a sanitized version of the array key
 */
function getArrayVal(array $array, $name)
{
    if (array_key_exists($name, $array)) {
        //use global HTMLPurifier object created in init.php
        global $purifier;
        if (!is_array($array[$name])) {
            $clean = $purifier->purify($array[$name]);
        } else {
            $clean = $array[$name];
        }
        return $clean;
    } else {
        return false;
    }
}
?>