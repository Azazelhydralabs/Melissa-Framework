import ast
def black_box(code):
    tree=ast.parse(code)
    tests=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='test_candidate']
    assert len(tests)==1 and len(tests[0].args.args)==1, 'one candidate parameter required'
    parameter=tests[0].args.args[0].arg
    parents={id(child):node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    denied_calls={'getattr','setattr','delattr','locals','globals','vars','eval','exec','compile','open','__import__'}
    denied_attrs={'__code__','__globals__','__closure__','__getattribute__','_getframe','currentframe','f_locals','f_globals','getsource','getfile'}
    for n in ast.walk(tree):
        if isinstance(n,(ast.Import,ast.ImportFrom)):
            modules=[n.module or ''] if isinstance(n,ast.ImportFrom) else [x.name for x in n.names]
            assert not any(m.split('.')[0] in {'inspect','os','sys','pathlib','subprocess','solution'} for m in modules), 'test must use black-box candidate, no source/process IO'
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Name): assert n.func.id not in denied_calls, 'dynamic introspection/IO denied'
        if isinstance(n,ast.Attribute): assert n.attr not in denied_attrs, 'function/frame/source inspection denied'
        if isinstance(n,ast.Name) and n.id==parameter:
            p=parents.get(id(n))
            direct=isinstance(p,ast.Call) and p.func is n
            callable_check=isinstance(p,ast.Call) and isinstance(p.func,ast.Name) and p.func.id=='callable' and len(p.args)==1 and p.args[0] is n
            assert direct or callable_check, 'candidate only direct calls, not alias/name/source inspection'
