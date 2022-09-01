/**
* foreach
*/
def fixForeach() {
    foreach_nodes = g.V.filter{ it.type == 'AST_FOREACH'}

    List _targets = [];
    for (_foreach in foreach_nodes)
    {
	def iter_data_id = _foreach.ithChildren(0).id.next(); 

	def iter_vars  = _foreach.children().filter{ it.childnum!=0&&it.type=='AST_VAR' }.out().filter{it.code!=null}.code.toList(); 

	key_nodes = _foreach.ithChildren(3).match{iter_vars.contains(it.code)}

	for (_k in key_nodes)
	{
	    Map _target = [:];
	    def _string = _k.code; 
	    def _id = _k.statements().next().id; 
	    _target[_id] = _string;
	    _targets.add(_target);
	    g.addEdge(g.v(iter_data_id), g.v(_id), 'REACHES', [var: _string]);
	}

    }
    return _targets;
}
