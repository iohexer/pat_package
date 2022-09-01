<?
	/**
	 * Makes an object safe to display in forms
	 *
	 * Object parameters that are non-string, array, object or start with underscore
	 * will be converted
	 *
	 * @param   object   $mixed        An object to be parsed
	 * @param   integer  $quoteStyle   The optional quote style for the htmlspecialchars function
	 * @param   mixed    $excludeKeys  An optional string single field name or array of field names not to be parsed (eg, for a textarea)
	 *
	 * @return  void
	 *
	 * @since   1.0
	 */
	function objectHtmlSafe(&$mixed, $quoteStyle = \ENT_QUOTES, $excludeKeys = '')
	{
		if (\is_object($mixed))
		{
			foreach (get_object_vars($mixed) as $k => $v)
			{
				if (\is_array($v) || \is_object($v) || $v == null || substr($k, 1, 1) == '_')
				{
					continue;
				}

				if (\is_string($excludeKeys) && $k == $excludeKeys)
				{
					continue;
				}

				if (\is_array($excludeKeys) && \in_array($k, $excludeKeys))
				{
					continue;
				}

				$mixed->$k = htmlspecialchars($v, $quoteStyle, 'UTF-8');
			}
		}
	}
?>