/**
* @return
*  1. function id
*  2. function name
*  3. class name
*  4. file path
*  5. parameters
*  6. returns
*  7. line count
*  8. callee times
*  9. branch time
*  10. loop time
**/
def getFuncInfo(node, trust_sans = false) {
	Map func_info = [:];
	func_name = getFuncName(node);

	for ( _func in func_name)
	{
	    func_info['func_id'] = _func.key; 
	    func_info['func_name'] = _func.value;
	}
	func_info['type'] = node.type;
	if (func_info['type'] != 'AST_FUNC_DECL')
	{
	    func_info['class_name'] = node.filter{it.classname != null}.classname;
	}
	func_info['file_name'] = findFile(node.id);
	 函数行数(不加头注释)
	func_info['size'] = getFuncSize(node.id);
	func_info['params'] = getFuncParams(node.id);
	func_info['returns'] = getFuncReturns(node.id);
	return func_info;
	func_info['be_called'] = node.inE('CALLS').count();
	func_info['branches'] = getFuncBranches(node.id);
	func_info['loops'] = getFuncLoops(node.id);
	func_info['callees'] = getFuncCalls(node.id);
	// callers
	func_info['callers'] =...;
	func_info['comments'] = getDocs(node.id);
	// codes
	func_info['codes'] = getCodes(node.id);
	// sinks
	def default_sinks = ["AST_ECHO", "AST_PRINT", "AST_EXIT"];
	func_info['sinks'] = g.v(node.id).match{default_sinks.contains(it.type)}.count();

	return func_info;
}

/**
*  get the file name of the target node
*
* @param node_id: id
*/
def findFile(node_id) {
    _node = g.v(node_id);

    if(!_node.funcid) 
    {
	    return _node.name;
    }
    else
    {
		findFile(_node.funcid);
    }
}


/**
* the information of the line count
*
* @param node_id: the function id
**/
def getFuncSize(node_id) {
	func_start = g.v(node_id).lineno;
	func_end = g.v(node_id).endlineno;
	return func_end+1-func_start;
}


/**
* get the parameters of the function
* @param node_id
* @return param_list
**/
def getFuncParams(node_id) {
	Map param_info=[:];

	def _params = g.v(node_id).children().has('type', 'AST_PARAM_LIST').children().count();
	return _params
	int count = 0;
	for (p_id in _params)
	{
		def _p = [];
		def _type = g.v(p_id).ithChildren(0).type.next();
		if (_type == 'AST_TYPE')
		{
			_type = g.v(p_id).ithChildren(0).flags.next()[0];
		}
		_p.add(_type);
		def _var = g.v(p_id).ithChildren(1).type.next();
		if (_var == 'string')
		{
			_var = g.v(p_id).ithChildren(1).code.next();
		}
		_p.add(_var)

		def _val = g.v(p_id).ithChildren(2).type.next();
		if (_val == 'AST_CONST')
		{
			_val = g.v(p_id).ithChildren(2).out().out().code.next();
		}
		_p.add(_val);

		param_info[count++] = _p;
	}

	return param_info;
}


/**
* analyze the return values
*
* @param node_id
* @return param_list
**/
def getFuncReturns(node_id) {
		List return_list = [];
		_returns = g.v(node_id).out('EXIT').in('FLOWS_TO').filter{it.type == 'AST_RETURN'}.children().type; // 函数出口从到exit点的控制流找
		return _returns;
}


/**
* get the comment information
*
* @param node_id: function id, default null
**/
def getDocs(node_id=null) {
	Map doc_info = [:];
	if (node_id == null)
	{
		doc_nodes = g.V.has('doccomment');
		for (_doc in doc_nodes)
		{
			doc_info[_doc.id] = _doc.doccomment;
		}
		return doc_info;
	}
	return g.v(node_id).has('doccomment').doccomment;
}



/**
* get all all code under a AST node 
* 
* @param node_id: node id
* @return code_list: all the code 
*/
def getCodes(node_id=null) {
	if (node_id == null)
	{
		Map code_info = [:];
		_funcs = g.V.filter{ isFuncDecl(it) }.id;
		for (func_id in _funcs)
		{
			List code_list = [];
			_codes = g.v(func_id).match{it.type == 'string'}.code;
			for (_code in _codes)
			{
				code_list.add(_code);
			}
			code_info[func_id] = code_list;
		}
		return code_info;
	}

	List code_list = [];
	_codes = g.v(node_id).match{it.type == 'string'}.code;
	for (_code in _codes)
	{
            code_list.add(_code);
	}
	return code_list;
}


/**
* get the token number
* @param node_id: node_id
* @param token_name
* @return the number of sub tokens
*/
def getTokensCount(node_id=null, token_name=null) {
	return tokens_count = g.v(node_id).match{ it.type == token_name }.count()
}


/**
* get the node information 
* @param node_id: 点id
*/
def nodeInfo(node_id) {
    Map res = [:];
    def _node = g.v(node_id)
    _file_name  = findFile(node_id);
    
    res['id'] = node_id;
    res['type'] = _node.type;
    res['lineno'] = _node.lineno;
    res['file_name'] = _file_name;    
    return res;
    
}

/**
* graphviz
*
*/
def showGraphNode(node_id) {
    res = '';
    def _file_name = findFile(node_id);
    def _node = g.v(node_id);
    def lineno = _node.lineno;
    res = _file_name+":"+lineno;
    return res;
}

def getSymbolName(node) {
	node_type = node.type;
	if (node_type == 'AST_VAR')
	{
		return node.varToName().next();	
	}
	else
	{
		_dim = node.ithChildren(0).next();
		if (_dim.type == 'AST_DIM')
		{
			getSymbolName(_dim)
		}
		else
		{
		    temp_name = node.ithChildren(0).varToName().next();
		}
		return temp_name;
	}
}


/**
*
* @param node_id: node id
* @return: get all of the callee name
**/
def getInnerCalls(node_id) {
    def _node = g.v(node_id);
    def _res = _node.match{isCallExpression(it) && it.id != node_id }.toList();
    _calls = [];
    for (_call in _res)
    {
	callee_name =  getCalleeName3(_call)[_call.id];
	if (callee_name)
	{
	    _calls.add(callee_name);
	}
    }
    return _calls;
}


/**
* the branches number
*
* @param node_id: node id
* @return: the branches in the function
**/
def getFuncBranches(node_id) {
    int _branches = 0;
    _branches += g.v(node_id).match{it.type == 'AST_IF_ELEM'||it.type == 'AST_SWITCH_CASE'}.count(); 
    return _branches;
}


/**
* the loops numbers
*
* @param node_id: node id
* @return: the loops in the function
**/

def getFuncLoops(node_id) {
    int _loops = 0;
    _loops += g.v(node_id).match{it.type == 'AST_FOREACH'||it.type == 'AST_FOR'||it.type=='AST_WHILE'||it.type=='AST_DO_WHILE'}.count(); 
    return _loops;
}


/**
* get all of the calls
*
* @param node_id: node_id 
* @return: the list of call name
*/
def getFuncCalls(node_id) {
    List func_calls = [];
    call_list =  g.v(node_id).match{isCallExpression(it)}.toList();
    for(_call in call_list)
    {
	def call_name;
	call_name =  getCalleeName2(_call);
	for (_name in call_name)
	{
	    func_calls.add(_name);
	}
    }
    return func_calls;
}