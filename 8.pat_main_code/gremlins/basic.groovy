Object.metaClass.isEchoExpression = { it -> 
    it.type == "a" ||
    it.type == "b"
}
Gremlin.defineStep('match', [Vertex, Pipe], { p ->
    _().nodes().filter(p)
})


// no closure
Object.metaClass.isFuncDecl = { it  ->
    it.type == "AST_FUNC_DECL" ||
    it.type == "AST_METHOD" ||
    it.type == "AST_STATIC_METHOD"
}


Object.metaClass.isCallExpression = { it -> 
    it.type == "AST_CALL" ||
    it.type == "AST_STATIC_CALL" ||
    it.type == "AST_METHOD_CALL"
}


Object.metaClass.isStatement = { it -> 
    it.parents().filter{ it.type == 'AST_STMT_LIST' }.count() == 1
}


Object.metaClass.isAssignment = { it -> 
    it.type == "AST_ASSIGN" ||
    it.type == "AST_ASSIGN_REF" ||
    it.type == "AST_ASSIGN_OP"
}


Gremlin.defineStep('parents', [Vertex, Pipe], { 
    _().in('PARENT_OF')
})


Gremlin.defineStep('match', [Vertex, Pipe], { p -> 
    _().astNodes().filter(p)
})


Gremlin.defineStep('matchParents', [Vertex, Pipe], { p -> 
    _().parents().loop(1) { !isStatement(it.object) } { p(it.object) }
})


Gremlin.defineStep('children', [Vertex, Pipe], { 
    _().out('PARENT_OF')
})


Gremlin.defineStep('ithChildren', [Vertex, Pipe], { i -> 
    _().children().filter{ it.childnum == i }
})


Gremlin.defineStep('lval', [Vertex, Pipe], { 
    _().filter{ isAssignment(it) }.ithChildren(0)
})


Gremlin.defineStep('rval', [Vertex, Pipe], { 
    _().filter{ isAssignment(it) }.ithChildren(1)
})

//AST_METHOD_CALL, AST_STATIC_CALL ithChidren(1) is method name
Gremlin.defineStep('nameToCall', [Vertex, Pipe], {
    _().ifThenElse{ !it.classname }{ it.parents().parents() }{ it.parents() }
})


Gremlin.defineStep('callexpressions', [Vertex, Pipe], { i -> 
    _().matchParents { isCallExpression(it) }
})


Gremlin.defineStep('echoexpressions', [Vertex, Pipe], { i -> 
    _().matchParents{ isEchoExpression(it) }
})


Gremlin.defineStep('statements', [Vertex, Pipe], { 
    _().ifThenElse{ isStatement(it) }
    { it }
            { it.parents().loop(1) { !isStatement(it.object) }}
})


Gremlin.defineStep('varToName', [Vertex, Pipe], { 
    _().filter{ it.type == 'AST_VAR' }.ithChildren(0).code
})


Gremlin.defineStep('astNodes', [Vertex, Pipe], {
    _().transform {
        def x = [] as Set;
        it.children().loop(1) { true } { true }
                .store(x).optional(2).transform { x + it }.scatter()
    }.scatter()
})


Gremlin.defineStep('toFile_rewriting', [Vertex, Pipe], {
    _().transform {
		func_id = it.funcid;
		_count = 1;
		while (_count < 3) {
		    it = it.parents();
		    func_id = it.funcid;
                    _count+=1
                }
		return func_id;
    }
})


// track
Gremlin.defineStep('ithParam', [Vertex, Pipe], { i ->
    _().children().has('type', 'AST_PARAM_LIST').ithChildren(i);
})


Gremlin.defineStep('ithParamToArg', [Vertex, Pipe], { i -> 
    //ith_param = _().ithParam(i);
    callers = _().in('CALLS').filter{ it.id != 4420 };
    target_args = callers.children().has('type', 'AST_ARG_LIST').ithChildren(i);
})


Gremlin.defineStep('paramsToArgs',[Vertex, Pipe], {
     def params = _().children().has('type', 'AST_PARAM_LIST').children();
	params.parents().parents().filter{!isFunc(it)}
})


Object.metaClass.isCall = { it ->
    it.type == 'AST_CALL'    ||
    it.type == 'AST_METHOD_CALL'    ||
    it.type == 'AST_STATIC_CALL'
}


Object.metaClass.isFunc = { it -> 
    it.type == 'AST_FUNC_DECL' ||
    it.type == 'AST_METHOD' 
}


Gremlin.defineStep('callToReturn', [Vertex, Pipe], {
    // filter消除switch情况下的break语句
    _().outE('CALLS').inV.outE('EXIT').inV.inE('FLOWS_TO').outV.filter{it.type == 'AST_RETURN'}
})


Gremlin.defineStep('containsCallNode', [Vertex, Pipe], {
    _().ifThenElse{ isAssignment(it) }
    {
        it
           .as('assign')
               .rval()
           .loop('assign')
            {
                it.object != null;
            }
            {
                true
            }
            .match
            { it.type == "AST_CALL" || it.type == "AST_METHOD_CALL" || it.type == "AST_STATIC_CALL" }
    }
    {
        it
           .astNodes()
           .match{ it.type == "AST_CALL" || it.type == "AST_METHOD_CALL" || it.type == "AST_STATIC_CALL" }
    }
})


Gremlin.defineStep('getMethodName', [Vertex, Pipe], {
    it.ithChildren(1).next().code
})


/**
* get function names from the the Decl. node
* including function, method, and static method
**/
def getFuncName(Vertex node) {
    def func_info = [:];
    if (node != null) 
    {
        if (node.type == 'AST_FUNC_DECL')
	{
	    func_info[node.id] = node.name;
        }
	else if (node.type == 'AST_METHOD')
	{
            if (node.flags.contains("MODIFIER_STATIC")) 
	    {
                _method_name = node.classname + "::" + node.name;
		func_info[node.id] = _method_name;
            }
            else
            {
                _method_name = node.classname +"->"+ node.name;
                func_info[node.id] = _method_name;
	    }
        }
    }
    return func_info;
}


/**
* get the call name from the call node.
* including function, method, and static method
**/
def getCalleeName(Vertex node) {
    def func_info = [:];
    if (node != null) 
    {
        if (node.type == 'AST_CALL')
	{
	    func_info[node.id] = node.ithChildren(0).out().next().code;
        }
	else if (node.type == 'AST_METHOD_CALL')
	{
	    // standard the object
	    _method_name = "object->" + node.ithChildren(1).next().code;
	    func_info[node.id] = _method_name;
        }
	else if (node.type == 'AST_STATIC_CALL')
	{
	    _method_name = "class::" + node.ithChildren(1).next().code;
	    func_info[node.id] = _method_name;
        }
    }
    return func_info;
}


def getCalleeName2(node) {
    List callee_info = [];
    if (node != null)
    {
        if (node.type == "AST_METHOD_CALL")
        {
	    class_name = node.ithChildren(0).out().next().code;
	    method_name = node.ithChildren(1).next().code;
	    _method = class_name+"->"+method_name;
            callee_info.add(_method);
        }
	else if (node.type == "AST_STATIC_CALL")
	{
	    class_name = node.ithChildren(0).out().next().code;
	    method_name = node.ithChildren(1).next().code;
	    _method = class_name + "::" + method_name;
	    callee_info.add(_method);
        }
	else
        {
            _func_name = node.ithChildren(0).out().next().code;
	    callee_info.add(_func_name)
        }
    }
    return callee_info;
}


Object.metaClass.getCalleeName_ob = { node_id ->
    def node = g.v(node_id);
    if (node != null)
    {
        if (node.type == "AST_METHOD_CALL")
        {
	    class_name = node.ithChildren(0).out().next().code;
	    method_name = node.ithChildren(1).next().code;
	    _method = class_name+"->"+method_name;
	    return method_name;
        }
	else if (node.type == "AST_STATIC_CALL")
	{
	    class_name = node.ithChildren(0).out().next().code;
	    method_name = node.ithChildren(1).next().code;
	    _method = class_name + "::" + method_name;
	    return method_name;
        }
	else
        {
            func_name = node.ithChildren(0).out().next().code;
	    return func_name;
        }
    }
}


/**
* another get callee name
*/
def getCalleeName3(node) {
    def call_id = node.id;
    Map callee_info = [:];
    if (node != null)
    {
        if (node.type == "AST_METHOD_CALL")
        {
	    class_name = node.ithChildren(0).out().next().code;
	    method_name = node.ithChildren(1).next().code;
	    _method = class_name+"->"+method_name;
            callee_info[call_id] = _method;
        }
	else if (node.type == "AST_STATIC_CALL")
	{
	    class_name = node.ithChildren(0).out().next().code;
	    method_name = node.ithChildren(1).next().code;
	    _method = class_name + "::" + method_name;
	    callee_info[call_id] = _method;
        }
	else
        {
            _func_name = node.ithChildren(0).out().next().code;
	    callee_info[call_id] = _func_name;
        }
    }
    return callee_info;
}



Gremlin.defineStep('containsLowSource', [Vertex, Pipe], {
    def _sources = ["_GET", "_POST", "_COOKIE", "_REQUEST", "_ENV", "HTTP_ENV_VARS", "HTTP_POST_VARS", "HTTP_GET_VARS"];
    _().ifThenElse { isAssignment(it) }
       {
           it.as('assign')
                .rval()
                .children()
              .loop('assign')
              {
                  it.object != null;
              } 
	      {
                   true
              }
	      .match{ it.type == "AST_VAR" || it.type == "string" }
	      .filter{ _sources.contains(it.varToName().next()); }
       }
       {
           it.astNodes()
	     .match{ it.type == "AST_VAR" || it.type == "string" }
	     .filter{ _sources.contains(it.varToName().next()); }
	     .in('PARENT_OF')
       }
	.dedup();
})

