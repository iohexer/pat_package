def track_var_test_1(node_id, target_var) {
   def back_nodes = [];
   //
   def _stmt = g.v(node_id).statements();
   back_stmts = _stmt.in('REACHES').id;
   if (back_stmts == [])
   {
        return null;
   }
   else
   {
        for (_b in back_stmts)
        {
            if (g.v(_b).type == 'AST_ASSIGN' || g.v(_b).type == 'AST_ASSIGN_OP')
            {
               def back = g.v(_b).ithChildren(0).match{it.type == 'string' && it.code !=null && target_var.contains(it.code)}.statements().toList();
               if (back != [])
               {
                   back_nodes += back;
               }
            }
            else if (g.v(_b).type == 'AST_FOREACH' || g.v(_b).type == 'AST_FOR' || g.v(_b).type == 'AST_IF' || g.v(_b).type == 'AST_SWITCH')
            {
                def back = g.v(_b).children().filter{it.type!='AST_STMT_LIST'}.match{it.type == 'string' && it.code != null && target_var.contains(it.code)}.statements().toList();
                if (back != [])
                {
                    back_nodes += back;
                }
            }
            else if (g.v(_b).type == 'AST_PARAM')
            {
                return [g.v(_b)];
            }
        }
    }

    return back_nodes;
}

def getCallParametersCode(_call) {
    return _call;
}

def getOutterCalls(node_id, only_name=false) {
    _calls =  g.v(node_id).as('back')
				.parents()
			  .loop('back')
			  {
			      it.object.id != g.v(node_id).statements().id;
			  }
			  {
				isCallExpression(it.object);
			  };

    call_list = [];
    for (_call in _calls)
    {
        call_list.add(getCalleeName3(_call));
    }
   
    if (only_name)
    {
	def call_names = [];
	for (_call in call_list)
        {
	    _call.each 
            {
	        call_names.add(it.value);
	    }
        }
	return call_names;
    }
    return call_list;
}

def findingTrans() {
    Map res = [:];
    def all_funcs = g.V.has('type', 'AST_FUNC_DECL'); // we didn't cover the method at this version
    def trust_sans = judgeTrustSans();
    // the string transform function must have the first parameter, and it is must be a string which need to be handled.
    // the first arg
    //def test = all_funcs.ithChildren(0).ithChildren(0).has('type', 'AST_PARAM').out.type;
    for (id in all_funcs.id)
    {
        def func_file = findFile(id);
        func_file = id+":"+func_file+":"+g.v(id).name+":"+g.v(id).lineno;

        if (g.v(id).ithChildren(0).out.toList() != [])
        {
            def func_first_param = g.v(id).ithChildren(0).ithChildren(0).filter{it.type=='AST_PARAM'}.children().type;

            // only view the 2th part of the frist parameter
            if (g.v(id).ithChildren(0).ithChildren(0).ithChildren(2).next().type != 'NULL')
            {
                def default_type = g.v(id).ithChildren(0).ithChildren(0).ithChildren(2).next().type;
                //
                if (default_type == 'integer')
                {
                    continue;
                }
                // remove the case like $a=null(AST_CONST->AST_NAME->null) temportary, as many sanitizers don't show this character.
                if (default_type == 'AST_CONST')
                {
                    continue;
                }
            }

            // detect whether the current parameter has data flows
            if (!g.v(id).ithChildren(0).ithChildren(0).filter{it.outE('REACHES').toList()!=[]})
            {
                continue;
            }

            // detect whether the function has no return
            if (!g.v(id).children.filter{it.type== 'AST_STMT_LIST'}.match{it.type == 'AST_RETURN'})
            {
                continue;
            }

            // check the default sans
            def is_trust_sans = false;
            if (trust_sans.contains(id))
            {
                is_trust_sans = true;
            }

            res[func_file] = getFuncInfo(g.v(id), is_trust_sans);
        }
    }

    return res;
}

/**
*
**/
def judgeTrustSans() {
    def all_funcs = g.V.has('type', 'AST_FUNC_DECL').id; // we didn't cover the method at this version

    def all_target_funcs = [];
    // get all the potential return stataments in the code base:w
    for (_func in all_funcs)
    {
        def first_arg_next_stmts = g.v(_func).ithChildren(0).ithChildren(0).out('REACHES').filter{it.type == 'AST_RETURN'};
        if (first_arg_next_stmts)
        {
            all_target_funcs.add(_func);
        }
    }

    // judge them
    def trust_sans_id = [];
    def trust_sans =["htmlspecialchars", "htmlentities", "strip_tags"];
    def is_move = true;
    while(is_move)
    {
        is_move = false;
        for (_func in all_target_funcs)
        {
            def _codes = g.v(_func).ithChildren(0).ithChildren(0).out('REACHES').filter{it.type == 'AST_RETURN'}.match{it.type == 'string'}.code;
            for (_code in _codes)
            {
                if (trust_sans.contains(_code))
                {
                    if (!trust_sans_id.contains(_func))
                    {
                        trust_sans_id.add(_func);
                        is_move = true;
                    }
                    if (!trust_sans.contains(g.v(_func).name))
                    {
                        trust_sans.add(g.v(_func).name);
                    }
                }
            }
        }
    }
    return trust_sans_id;
}


def check_sources(target_sources, sources) {
    Map res = [:];
    boolean flag = true;
    List black_sources = [];

    for (t in target_sources)
    {
        def args = g.v(t).in('CALLS').children().filter{it.type == 'AST_ARG_LIST'}.match{it.type == 'string'}.code;
        for (arg in args)
        {
            if (['_GET', '_POST', '_COOKIE', '_REQUEST'].contains(arg))
            {
                flag = false;
                break;
            }

            if (sources.contains(arg))
            {
                flag = false;
                break;
            }
        }
    }
    return flag;
}

