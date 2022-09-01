<?php
class global_class {
    public function cleanvars($input, $allow_html = false)
    {
        $config = array('elements' => '-*');

        if ($allow_html) {
            $config = array('safe' => 1, 'elements' => 'a, ol, ul, li, u, strong, em, br, p', 'deny_attribute' => '* -href');
        }

        return str_replace(array('&lt;', '&gt;', '&amp;'), array('<', '>', '&'), htmLawed($input, $config));
    }
}
?>