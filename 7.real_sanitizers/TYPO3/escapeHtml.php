<?php
class DebugExceptionHandler extends AbstractExceptionHandler
{
    protected function escapeHtml(string $str): string
    {
        return htmlspecialchars($str, ENT_COMPAT | ENT_SUBSTITUTE);
    }
}
?>