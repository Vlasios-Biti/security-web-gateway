"""Static inventory of application functions and declared HTTP endpoints."""
import ast
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def inventory():
    functions=[];routes=[]
    for path in sorted((ROOT/'app').rglob('*.py')):
        tree=ast.parse(path.read_text(encoding='utf-8'));relative=path.relative_to(ROOT).as_posix()
        for node in ast.walk(tree):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                functions.append({'file':relative,'name':node.name,'line':node.lineno,'end':node.end_lineno})
        if path.parent.name!='routers':continue
        constants={}
        for node in tree.body:
            if isinstance(node,ast.Assign):
                for target in node.targets:
                    if isinstance(target,ast.Name):
                        try:constants[target.id]=ast.literal_eval(node.value)
                        except (ValueError,TypeError):pass
        prefix=''
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and getattr(node.func,'id',None)=='APIRouter':
                for item in node.keywords:
                    if item.arg=='prefix':prefix=constants.get(getattr(item.value,'id',''),getattr(item.value,'value',''))
        for node in tree.body:
            if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
            for decorator in node.decorator_list:
                if not isinstance(decorator,ast.Call) or not isinstance(decorator.func,ast.Attribute) or decorator.func.attr not in ('get','post','put','delete','patch'):continue
                defaults=dict(zip([arg.arg for arg in node.args.args][-len(node.args.defaults):],node.args.defaults)) if node.args.defaults else {}
                fields=[];files=[]
                for name,default in defaults.items():
                    if isinstance(default,ast.Call):
                        if getattr(default.func,'id',None)=='Form':fields.append(name)
                        if getattr(default.func,'id',None)=='File':files.append(name)
                routes.append({'file':relative,'name':node.name,'line':node.lineno,'method':decorator.func.attr.upper(),'path':prefix+ast.literal_eval(decorator.args[0]),'fields':fields,'files':files})
    return {'functions':functions,'routes':routes}


if __name__=='__main__':
    import json
    print(json.dumps(inventory(),indent=2))
