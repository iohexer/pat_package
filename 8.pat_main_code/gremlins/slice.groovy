/**
* find all the sanitizer call site
*
* @param sanitize_list
* @return sanitize_calls
**/
def getSanitizeCalls(sanitize_list) {
	def sanitize_calls = [:];
	for (_san in sanitize_list)
	{
		def _calls = [];
	    //_calls = g.v(_san).in('CALLS').filter{!sanitize_list.contains(it.funcid.toString())}.id.dedup().toList();
		def san_codes = g.V().has('code', _san);
		for (code in san_codes)
		{
			def call_node = code.parents().parents();
			if (call_node.type.next() == 'AST_CALL')
			{
				_calls.add(code.parents().parents().id.next());
			}
			else
			{
				def method_call_node = code.parents();
				try 
				{
					if (method_call_node.type.next() == 'AST_METHOD_CALL' ||
						method_call_node.type.next() == 'AST_STATIC_CALL')
					{
						_calls.add(code.parents().id.next());
					}

				}
				catch(Exception e)
				{
					continue;
				}
			}
		}
	    sanitize_calls[_san] = _calls;
	}
	return sanitize_calls
	// check the original sanitizers
	for (_san in ["htmlspecialchars", "htmlentities", "trip_tags"])
	{
	   _calls = g.V.filter{ it.code == _san}.filter{!sanitize_list.contains(it.funcid.toString())}.parents().filter{it.type == 'AST_NAME'}.parents().id.dedup().toList();
	   sanitize_calls[_san] = _calls;
	}
	return sanitize_calls;
}


//--------------------------- forward slice --------------------
/**
*
* find the sink
*
* @param sanitize_calls
* @return path_list
**/
def sliceFDPaths(sanitize_calls, arg=null) { 
    call_fd_paths = [:];
    for (_call in sanitize_calls)
    {
def call_site = g.v(_call);
	if (call_site.statements().outE('REACHES').toList() == []) 	
	{ 
	    call_fd_paths[_call] = [];
	    continue;
	}
	else if (call_site.children().has('type', 'AST_ARG_LIST').children().match{it.type == 'AST_DIM'}.toList() != []) //是个call
        {
	    def dim_arg = call_site.children().has('type', 'AST_ARG_LIST').children().match{it.type == 'AST_DIM'}.id;

	    if (dim_arg)
	    {
			call_fd_paths[_call] = ["array"];
	    }
            continue;
	}
        else 
	{
	    _paths = call_site.statements()
	 	      .as('sloop')
			.out('REACHES')
		      .loop('sloop')
		      {
		         it.loops<15;
		      }
		      {
			 it.object.out('REACHES').toList() == [];
		      }.dedup().path();	

	    List path_list = [];

	    for (_path in _paths) 
	    {
	        List node_list = [];
	        for (_node in _path) 
	        {
	            node_list.add(_node.id);
	        }
	            path_list.add(node_list);
	    }		       
	    call_fd_paths[_call] = path_list;
	}
    }
    return call_fd_paths;
}


/**
*
* @param all_fd_list 
* @return: fd_last_callee_info:{call_name: ith_arg}
**/
def sliceFDLast(all_fd_list, inline_call=false) {
	List fd_info_list = []

	for (last_id in all_fd_list)
	{
	    Map fd_last_info = [:];

	    def last_node = g.v(last_id);	
	    def _id = last_node.id;
	    def _type = last_node.type;

	    
	    if (inline_call) 
	    {
		_stmt = g.v(last_id).statements().next();
		fd_last_info['id'] = _stmt.id;
		fd_last_info['type'] = _stmt.type;

	        def outter_calls  = getOutterCalls(_id, true); 
	        fd_last_info['outter_calls'] = outter_calls;
	    }
	    else
	    {
		    fd_last_info['id'] = _id;
		    fd_last_info['type'] = _type;

		    if (_type == 'AST_CALL'||_type == 'AST_METHOD_CALL'||_type == 'AST_STATIC_CALL')
		    {
			call_name =  getCalleeName3(last_node)[_id];
			fd_last_info['name'] = call_name;
		    }
	    }
	    fd_info_list.add(fd_last_info);
	}
	return fd_info_list;
}


/**
* the arg site
* 
* @param last_node
* @param taint_name
* @return the site of the taint
**/
def getTaintArgSite(last_node, taint_name='last') {
	if (taint_name == 'last')
	{
		_args = last_node;
	}
	else
	{
		_args = last_node.match{ it.code == taint_name };
	}
	taint_args = [:];
	for (_arg in _args)
	{
		if( _arg.parents().type == 'AST_NAME' )
		{
			return _arg;
		}
		arg_list =  _arg.as('sloop')
					    .parents()
						.filter{ it.type !='AST_NAME'} 
					.loop('sloop')
					{
						it.object.type != 'AST_STMT_LIST';
					}
					{
						it.object.type == 'AST_ARG_LIST';
					}.path().toList();

		longest_arg_list = [];
		max_size = 0;
		for (_list in arg_list)
		{
			_size = _list.toList().size();
			if (_size > max_size)
			{
				max_size = _size;
				longest_arg_list=_list;
			}
		}
		if (longest_arg_list == []) 
		{
			continue;
		}
		taint_site = longest_arg_list[-2].childnum;
		taint_args[_arg.id] = taint_site;
	}
		return taint_args;
}


//----------------------------- backwordk  -----------------------------
/**
*  find sources
*
* @param sanitize_calls
* @return  path_list
**/
def sliceBDPaths(sanitize_calls) {
    Map call_bd_paths = [:];

    for (_call in sanitize_calls)
    {
		call_site = g.v(_call); 
        if (call_site.statements().inE('REACHES').toList() == [])
		{
	    	call_bd_paths[_call] = [];
		}
		else
		{
			sanitize_args = call_site.children()
							.has('type', 'AST_ARG_LIST').next().ithChildren(0)
							.match
							{
								it.type == 'string' && it.parents().type != 'AST_NAME';
							}.code.toList(); 
			List next_stmts = [];	    
			for (_arg in sanitize_args)
			{
				if (_arg == null)
				{
					continue;
				}

				def _nexts = track_var_test_1(_call, _arg);
				if (_nexts == [])
				{
					next_stmts = [];
					continue;
				}
	        	for (_next in _nexts)
				{
		    		if (_next!=null && !next_stmts.contains(_next))
		    		{
						next_stmts.add(_next);  
		 			}
				}
	 	   	}
	    	if (next_stmts == [])   
	    	{
				call_bd_paths[_call] = []; 
	 	    }
	    	else
	    	{
	       		List path_list = []; 
	       		for (_next in next_stmts)
	       		{ 
					if (_next.in('REACHES').toList() == []) 
		    		{
		        		path_list.add([_call, _next.id]);
		    		}
	            	else
		    		{
		        		_paths = _next.as('backward')
				    			.in('REACHES')
				  				.loop('backward')
				   				{
				       				it.loops<30;
				   				}
				   				{
				       				it.object.in('REACHES').toList() == [];
				   				}.dedup().path().toList(); 
			
						for (_path in _paths)
		        		{
			    			List path_nodes = [_call]; 
			    			for (_node in _path)
			    			{
			        			if (_node && _node.type != null && !path_nodes.contains(_node.id)) 
			        			{
				    				path_nodes.add(_node.id);
			        			}
			    			}
			    			path_list.add(path_nodes);
		        		} 
		    		}
	    		}	 
				call_bd_paths[_call] = path_list; 
	    	}
		}
    }
	return call_bd_paths;
}


/**
* slice backward
* 
* @param all_bd_list
* @param inner_call
* @return: bd_last_callee_info
**/
def sliceBDLast(all_bd_list, inline_call=false) {
	List bd_info_list = [];
        List expr_list = [];
	for (last_id in all_bd_list)
	{
	    Map bd_last_info = [:];	
	    def last_node = g.v(last_id);
	    
	    def _id = last_node.id;
	    def _type = last_node.type;
            	
	    if (inline_call) 
	    {
			_stmt = g.v(last_id).statements().next();
			bd_last_info['id'] = _stmt.id;
			bd_last_info['type'] = "inner"; 

			def inner_calls = getInnerCalls(last_id); 
			bd_last_info['inner_calls'] = inner_calls;

			def inner_strings = g.v(last_id).children().has('type','AST_ARG_LIST').match{it.type=='string' && it.parents().type.next()!='AST_NAME'}.code.toList();
			bd_last_info['inner_strings'] = inner_strings;
	    }
	    else 
        {
			bd_last_info['id'] = _id;
			bd_last_info['type'] = _type;

			if (_type == 'AST_CALL' || _type == 'AST_METHOD_CALL' || _type == 'AST_STATIC_CALL')
			{
				call_name = getCalleeName3(last_node)[_id];
				bd_last_info['name'] = call_name;
			}
			else if (_type == 'AST_ASSIGN' || _type == 'AST_ASSIGN_OP') 
			{
				def _rval = last_node.rval().next();
				def rval_id = _rval.id;
				def rval_type = _rval.type;
				bd_last_info['stmt_rval'] = rval_type;
				def stmt_calls = getInnerCalls(_id);
				bd_last_info['stmt_calls'] = stmt_calls;

				def stmt_strings = g.v(rval_id).match{it.type == 'string' && it.parents().type.next()!='AST_NAME'}.code.toList();
				bd_last_info['stmt_strings'] = stmt_strings;
        	}
	        else if (_type == 'AST_EXPR_LIST') 
	        {
				if (expr_list && expr_list.contains(_id))
				{
					continue;
				}
				expr_list.add(_id);
	        }
			else   
			{
		      bd_last_info['unknow'] = _type;
			}
	    }
	    bd_info_list.add(bd_last_info);
	}
	return bd_info_list;
}

def countReaches_sink(String key_word, List sanitizer_list=["htmlspecialchars", "htmlentities", "strip_tags"]) {
	if (key_word.split("->").length > 1)
	{
		key_words = key_word.split("->");
		key_word = key_words[key_words.length-1];
		_codes = g.V.filter{it.code == key_word}.parents().filter{it.type == 'AST_METHOD_CALL'};
	}
	else if (key_word.split("::").length > 1)
	{
		key_words = key_word.split("::");
		key_word = key_words[key_words.length-1];
		_codes = g.V.filter{it.code == key_word}.parents().filter{it.type =='AST_STATIC_CALL'};
		return _codes.count();
	}

	else 
	{
		_codes = g.V.filter{it.code == key_word}.parents().parents().filter{it.type == 'AST_CALL'};
	}
	def taints = _codes.as('sloop').in('REACHES').loop('sloop') 
	{
		it.loops<10;
	}
	{
		it.object.type == 'AST_ASSIGN';
	}.dedup().path().dedup();
	def _count = 0;
	for (taint in taints)
	{
		for (node in taint)
		{
			if (node.match{sanitizer_list.contains(it.code)})
			{
				_count+=1;
			}
		}
	}

	return _count;
}


def countReaches_source(String key_word, List sink_apis=[]) {
	def _stmts;
	def target_sinks = [];
	if (sink_apis != [])
	{
		for (_sink in sink_apis)
		{
			target_sinks.add(_sink.split_method(_sink));
		}
	}

	// static call
	if (key_word.indexOf("::") != -1)
	{
		key_word = key_word.split("::").last();
		_stmts = g.V.filter{it.code == key_word}.parents().filter{it.type == 'AST_STATIC_CALL'}.statements().id;
	}
	// method call
	else if (key_word.indexOf("->") != -1)
	{
		key_word = key_word.split("->").last();
		_stmts = g.V.filter{it.code == key_word}.parents().filter{it.type == 'AST_METHOD_CALL'}.statements().id;
	}
	else
	{
		_stmts = g.V.filter{it.code == key_word}.parents().filter{it.type == 'AST_NAME'}.statements().filter{it.type != 'AST_IF'&&it.type != 'AST_SWITCH'&&it.type != 'AST_CONDITIONAL'&&it.type!='AST_RETURN'}.id; 
	}

	int _count = 0;
	//
	for (_stmt in _stmts)
	{
		if (g.v(_stmt).type == 'AST_ECHO' || g.v(_stmt).type == 'AST_EXIT' || g.v(_stmt).type == 'AST_PRINT')
		{
			_count+=1;
		}
		else
		{
			def res = g.v(_stmt).as('sloop').out('REACHES').loop('sloop')
			{
				it.loops<10;
			}
			{
				it.object.out('REACHES').toList()==[];
			}.statements().id.toList();

			//
			for (i in res)
			{
				def t = g.v(i).type;
				if (t == 'AST_ECHO' || t == 'AST_PRINT' || t == 'AST_EXIT')
				{
					_count += 1;
				}
				if (t == 'AST_CALL' || t == 'AST_METHOD_CALL' || t == 'AST_STATIC_CALL')
				{
					if (target_sinks!=[] && target_sinks.contains(i.match{it.type == 'string'}.code))
					{
						_count += 1;
					}
				}
			}
		}
	}
	return _count;
}


//====== checks =====

/**
*
**/
def check_infer_apis(infer_apis) {
	// check whether the apis have a function body
	def correct_list = [];
	for (_api in infer_apis)
	{
		if (g.V.filter{it.name == _api})
		{
			correct_list.add(_api);
		}
	}
	return correct_list;
}

/**
* split the method from method_call or static_call
**/
def split_method(func_name) {
	if (func_name.indexOf("::") != -1)
	{
		func_name = func_name.split("::").last();
	}
	else if (func_name.indexOf("->") != -1)
	{
		func_name = func_name.split("->").last();
	}
	return func_name;
}

