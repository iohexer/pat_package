class Scanner {
	def g;
	List source_list = [];
	List sink_list = [];
	List sanitize_list = [];

	List intra_path = []; 
	List taint_link = [];   
	List _visited = [];
	Map taint_link_info = [:];
	List unknow_calls = []; 
	List taint_parameters = []; 
	int track_param = 0;  // cross params
	int link_id = 1;


	def Scanner(graphObj, sanitize_info=[], source_info=[], sink_info=[]) {
		this.g = graphObj;
		this.sanitize_list = sanitize_info;
		if (source_info != [])
		{
		    this.source_list = source_info;
		}
		else
		{
		    this.source_list = ["_GET", "_POST", "_COOKIE", "_REQUEST"];
		}
		this.sink_list = sink_info;
	}


	/**
	 *   load default xss sinks
	 */
	def loadDefaultXSS() {
	     List sink_nodes = [];
		 // the default sinks are the tokens of the PHP 
	     sink_nodes = g.V
			   .filter{ it.type == 'AST_ECHO' || it.type == 'AST_PRINT' || it.type == 'AST_EXIT'}
			   .filter{ it.children().next().type != 'string' && it.children().next().type != 'NULL' }
			   .toList(); 
	     return sink_nodes;

	}


	/**
	 *  load user-defined sinks
	 */
	def loadUserSinks(_sink, _arg=0) {
		List sink_nodes = [];	
		sink_nodes = g.V
			      .filter{ it.code == _sink && isCallExpression(it.parents().next())}.toList();
	        return sink_nodes;
	}
	

	/**
	 *  load sinks
	 *  
	 *  @return: all the sinks
	 */
	 def loadSinks() {
	     List sink_nodes = [];
	     // 如果没有sink_list, 找默认的xss
	     if (this.sink_list == []) 
	     {
			sink_nodes = loadDefaultXSS()
	     }
	     else
	     {
			for (_sink in this.sink_list)
			{
		    	sink_nodes = loadUserSinks(_sink);
			}
	     }
	     return sink_nodes;	
	}


	def start() {
	    List sink_nodes;
        sink_nodes = this.loadSinks();
	    for (_sink in sink_nodes)
	    {
		    def sink_id = _sink.id;
	        this.taintTrack(_sink, 1); 
		    this.taint_link_info[_sink.id] = taint_link; 
		    this.taint_link = []; 
		    this.link_id = 1;
    	}

	    def res = [];
	    res.add(this.taint_link_info);
	    res.add(this.unknow_calls);
	    res.add(this.taint_parameters);

	    return res;
	}


	/**
	* taint analysis
	* 
	* @param sink_node 
	* @param _caller 
	* @return: all the taint paths
	**/
	def taintTrack(sink_node, _caller='', _count) {
	    this.intra_path = []; 
	    Map _path = [:];
	    _path["link_id"] = this.link_id; 

	    this.link_id+=1;
	    _path["func_id"] = sink_node.funcid; 

	    if (_count == 1) 
	    {
	        _path["sink"]  = sink_node.id;
	    }
	    else if (_count > 1 && sink_node.type == 'AST_RETURN')
	    {
		    _path["to_return_site"] = sink_node.id;
	    }

	    _path["taints"] = flowBackWard(sink_node.statements().next(), 1); 	   
	    _path["taints"] = flowBackWard(sink_node, 1); 	   
	    _path["seq"] = _count;

 	    if (_caller != '')
	    {
	        _path["from_call_site"] = _caller;
	    }

	    for (_taint in _path["taints"])
	    {
		    if (_taint["calls"])
	  	    {
		        for (_call in _taint["calls"])
		        {
			        def call_node;
			        call_node = this.g.v(_call);
			        def _returns;
			        _returns = call_node.callToReturn().toList();
			        if (_returns)
			        {
			            for (_return in _returns)
			            {
			 	            if (_return.funcid != sink_node.funcid)
			                {
				                taintTrack(_return, call_node.id, _count+1);
				            }
			            }
			        }
			        else
		            {
			            this.unknow_calls.add(_call);
                    }
		        }
		    }

		    if (_taint['type'] == 'AST_PARAM')
		    {
			    this.taint_parameters.add(_taint)
			    if (this.track_param == 1) 
			    {
			        this.track_param = 0;
			        def taint_call_args = jumpToCallSiteArgs(_path['func_id'], _taint['id'])
			        for (_call in taint_call_args)
			        {
				        taintTrack(_call, _call.id, _count+1);
			        }
			    }
		    }
	    }
	            this.taint_link.add(_path);
        }


	def jumpToCallSiteArgs(func_id, node_id) {
	    def ith_param = g.v(node_id).childnum;
	    def call_sites = g.v(func_id).in('CALLS');
	    return call_sites;
	}


	def flowBackWard(_node, _count) {

        this._visited.add(_node);
	    Map _visit = [:];
	    _visit['id'] = _node.id;
	    _visit['step'] = _count;
	    _visit['type'] = _node.type;
	    this.intra_path.add(_visit);

	    def _sources;
	    _sources = _node.match{this.source_list.contains(it.code)}.transform{it.id}.toList();
	    if (_sources!=[])
	    {
		 _visit['sources'] = _sources;
	    }

	    def _calls;
	    _calls = _node.match{ isCallExpression(it) }.transform{it.id}.toList();

	    if (_calls!=[])
	    {
		_visit['calls'] = _calls;
		List unknow_calls = [];
		for (_call in _calls)
	        {
		    def _returns;	
		    _returns = g.v(_call).callToReturn().toList();
		    if (_returns == [])
		    {
				unknow_calls.add(_call);
            }
		    else
		    {
			    _visit['call_returns'] = g.v(_call).callToReturn().transform{it.id}.toList();
		    }
                }
		if (unknow_calls != [])
		{
		   _visit['unknow_calls'] = unknow_calls;
		}
	    }
	    if (_node.in('REACHES'))
	    {
	       for(_next in _node.in('REACHES'))
	       {
		       if(!(_next in this._visited))
		   		{
		         	flowBackWard(_next, _count+1);
		   		}
			}
	    }
	    return this.intra_path;
	}

def intraTrack(_start, _end) {
    def taint_var = [];
    def start_site = this.g.v(_start);

    if (start_site.type == "string")
    {
		taint_var = this.g.v(_start).code;
    }
    else
    {
		taint_var = this.g.getCalleeName_ob(start_site.id);
    }

    def start_node = this.g.v(_start).statements();
    def _paths = start_node.as('sloop')
                               .out('REACHES')
                            .loop('sloop')
                             { 
                               it.loops<30;
                             }
                             {
                               it.object.id == _end || it.object.id == this.g.v(_end).statements().id.next();
                             }.path().dedup()
                              .transform{it.id}.toList();
    _paths = _paths.each{it.unique()}.unique();

    if (_paths.size()>=10)
    {
		_paths = _paths.subList(1, 10);
    }
    def _stmts = [:];
    if (_paths == [])
    {
		def stmt_info = [:];
		stmt_info['stmt_id'] = _end;
		stmt_info['taint_var'] = taint_var;
		stmt_info['callee_list'] = taintCalleeInStmt(_start, taint_var);
		stmt_info['lineno'] = this.g.v(_end).lineno;
		stmt_info['bip'] = taintBOPInStmt(_start, taint_var)
		stmt_info['flag'] = taintCastInStmt(_start, taint_var)
		return _stmts;
    }

    def _count = 1;
    for(_path in _paths) 
    {
		def _key = '';
		for (def i=0; i<_path.size(); i++)
		{
			if (i+1!=_path.size())
			{
				_key+=_path[i].toString()+":";
			}
			else
			{
				_key+=_path[i].toString();
			}
		}
			_stmts[_key] = intraPath(taint_var, _path);
			_count+=1;
    }
    return _stmts;
}

def intraPath(taint_var, _path) {
	def stmt_info_list = [];
	def stmt_info = [:];
	for ( def i=0; i<_path.size(); i++)
	{
	    def _curr = _path[i];
	    stmt_info['stmt_id'] =  _curr;
	    stmt_info['lineno'] = g.v(_curr).lineno;
	    stmt_info['taint_var'] = taint_var; 
	    stmt_info['callee_list'] = taintCalleeInStmt(_curr, taint_var);
		stmt_info['bip'] = taintBOPInStmt(_curr, taint_var);
	    stmt_info['flag'] = taintCastInStmt(_curr, taint_var);
		if (stmt_info['flag'] == '') 
		{
			stmt_info['flag'] = taintObjectInStmt(_curr, taint_var);
		}
	    stmt_info_list.add(stmt_info);
	    stmt_info = [:];

	    def _next =  _path[i+1];	
	    if (_next == null)
  	    {
		break;
            }
	    else
	    {
	        taint_var = this.g.v(_curr).outE('REACHES').filter{it.inV.id.next() == _next}.var.next();
	    }
	}
	return stmt_info_list;
    }


def taintCalleeInStmt(_curr, taint_var) {
    //def taint_var_list = this.g.v(_curr).outE('REACHES').filter{it.inV.id.toList().contains(_next)}.var;
    def target_node = this.g.v(_curr);

	if (!target_node.match{it.code == taint_var})
	{
		return [];
	}

    def taint_site = target_node.match{it.code == taint_var}.next();
    def next_site = taint_site;
    def res = this.g.v(_curr).match{it.code == taint_var}
	                .as('sloop').parents().loop('sloop')
					{
						it.object.id !=_curr;
					}
					{
						it.object.parents().next().type == 'AST_ARG_LIST';
					}.transform
					{
						def info=[:];
						info['ith'] = it.childnum;
						info['callee'] =  g.getCalleeName_ob(it.parents().parents().next().id);
						return info;
					}
    return res;
}


def taintCastInStmt(_curr, taint_var) {
    def flag = "";
    def target_node = this.g.v(_curr);
    if (target_node.filter{it.children().type.toList().contains('AST_CONDITIONAL')})
    {
	def conditional_res_1 = target_node.children().filter{it.type=='AST_CONDITIONAL'}.ithChildren(1);
	def conditional_res_2 = target_node.children().filter{it.type=='AST_CONDITIONAL'}.ithChildren(2);
	if (!conditional_res_1.match{it.code == taint_var} && !conditional_res_2.match{it.code == taint_var})
	{
	    flag = "bool";
	}
    }
    if (target_node.filter{it.ithChildren(1).flags.toList().contains(['BINARY_BOOL_AND'])})
    {
	flag = "bool";
    }
    
    if (target_node.match{it.type == "AST_CAST"}.toList() != []) 
    {
	def cast_type = target_node.match{it.type == "AST_CAST"}.next().flags[0];
        if(cast_type == "TYPE_LONG")
        {
	    flag = "bool";
        }
    }

    return flag;
}

def taintObjectInStmt(_curr, taint_var) {
	def flag;
	def strs = g.v(_curr).match{it.type == 'string'}.id;

	if (!strs)
	{
		return;
	}

	for (s in strs)
	{
		if (g.v(s).code == taint_var)
		{
			def _type = g.v(s).parents().parents().type.next();
			if (_type == 'AST_PROP')
			{
				return "prop";
			}
		}
	}
	return ""; 
}

def taintBOPInStmt(_curr, taint_var) {
	return _curr;
	def flag;
	def strs = g.v(_curr).match{it.type == 'string'}.id;

	if (!strs)
	{
		return;
	}
	return g.v(_curr).match{it.type == 'AST_CONDITIONAL'}.type;
}


	def taintTrack2(sink_node, from_path=[]) {
	    def sink_id = sink_node.id;
	    List intra_paths = flowBackWard2(sink_node).toList();
	    def inline_source = sink_node.match{this.source_list.contains(it.code)}.toList();
	    if (inline_source != [])
	    {
		this.taint_link.add(sink_id);
	    }

	    for (_path in intra_paths)
	    {
	        for (_taint in _path)
	        {
		    // source
		    def _sources = this.g.v(_taint).match{ this.source_list.contains(it.code) }.toList();
		    if (_sources != [])
		    {
		        this.taint_link.add(_path+from_path);
		    }
		    
		    // calls
		    def _calls  = this.g.v(_taint).match{ isCallExpression(it) }.toList();
		    if (_calls != [])
		    {
		        for (_call in _calls)
		        {
			    def _returns = _call.callToReturn().toList();
			    if (_returns != [])
			    {
			        for (_return in _returns)
			        {
				    if (_return.funcid != sink_node.funcid)	
				    {
					_path = _path.toList();
				        this.taintTrack2(_return, _path+from_path);
				    }
				}
			    }
			}
		    }
		}
	    }
	    return this.taint_link;
        }


	def flowBackWard2(_node) {
            List res = _node.as('sloop')
                             .in('REACHES')
			     .loop('sloop')
		  	     {
				it.loops<30;
			     }
			     {
				!it.object.inE('REACHES');
   			     }.path().transform{it.id}.toList();
	    if (res == [])
	    {
		def node_id = _node.id;
		res.add([node_id]);
	    }
	    return res;
        }
}
