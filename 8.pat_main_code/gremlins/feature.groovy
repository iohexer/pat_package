/**
* get the target features
* ~~~~~~~~~~~~~~~~
*
*/

def showUnknowCalls(List unknow_calls) {
    def call_name_list = []

    {
	call_node = g.v(_call);
	call_name_list.add(getCalleeName3(call_node));
    }	
    return call_name_list;
}

/**
* 
* detect whether there are some flows from the para to return
* (judge a string transform function)
*
* @param pre_sanitizes: the potential sanitizes list, which have make sure
* 						have at least one parameter and one return.
* @return: the functions that have validation function
*/
def paramToReturn(pre_sanitizes) {
    def res = [];
    for (_san in pre_sanitizes)
    {
	_node = g.v(_san)	
	if (_node)
	{
		param_nodes = _node.children().filter{it.type == 'AST_PARAM_LIST'}.children().filter{ it.out('REACHES').toList()!=[] }; 
		param_nodes.as('sloop').out('REACHES').loop('sloop')
				 	   {
						it.loops<30;
					   }
					   {
						it.object.type == "AST_RETURN";
					   }
		if (param_nodes)
		{
		    res.add(_san);
		}
	}
	
    }
    return res;
} 


def judgeBuiltIn(pre_sanitizes) {
    List built_in = ["htmlspecialchars", "htmlentities", "strip_tags", "_san", "_encode", "_replace", "_check"]
    List new_built_in = []
    for (_san in pre_sanitizes)
    {
        _func = g.v(_san);
	if (_func)
	{
	    _match = _func.children().has('type', 'AST_STMT_LIST').match{ built_in.contains(it.code) }.parents().has('type', 'AST_NAME');
	}
        if (_match)  
        {
	   		new_built_in.add(_san);
        }
    }
    return new_built_in;
}


/**
* parse the rules of str_replace() ;
*
**/
def handle_str_replace(node_id) {
	Map rules = [:];
	def str_replaces = g.v(node_id).match{it.code == 'str_replace'}.parents().parents().has('type', 'AST_CALL').ithChildren(1).id.toList();

	for(_p in str_replaces)
	{
		rules[_p] = g.v(_p).ithChildren(0).type.next();

		def search_exp = g.v(_p).ithChildren(0).type.next();
		if (search_exp == 'string')
		{
			def _search = g.v(_p).ithChildren(0).code;
			def _replace = g.v(_p).ithChildren(1).code;
			rules["search"] = _search;
			rules["replace"] = _replace;
		}
		else if (search_exp == 'AST_ARRAY')
		{
			def _search = g.v(_p).ithChildren(0).match{it.type == 'string'}.code;
			def _replace = g.v(_p).ithChildren(1).match{it.type == 'string'}.code;
			rules["search"] = _search;
			rules["replace"] = _replace;

		}
	}

	return rules;
}


/**
* parse the rules of preg_replace() ;
*
**/
def handle_preg_replace(node_id) {
	Map rules = [:];
	def str_replaces = g.v(node_id).match{it.code == 'preg_replace'}.parents().parents().has('type', 'AST_CALL').ithChildren(1).id.toList();

	for(_p in str_replaces)
	{
		rules[_p] = g.v(_p).ithChildren(0).type.next();

		def search_exp = g.v(_p).ithChildren(0).type.next();
		if (search_exp == 'string')
		{
			def _search = g.v(_p).ithChildren(0).code;
			def _replace = g.v(_p).ithChildren(1).code;
			rules["search"] = _search;
			rules["replace"] = _replace;
		}
		else if (search_exp == 'AST_ARRAY')
		{
			def _search = g.v(_p).ithChildren(0).match{it.type == 'string'}.code;
			def _replace = g.v(_p).ithChildren(1).match{it.type == 'string'}.code;
			rules["search"] = _search;
			rules["replace"] = _replace;

		}
	}
	return rules;
}
