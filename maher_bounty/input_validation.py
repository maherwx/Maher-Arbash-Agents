from __future__ import annotations

MAX_FUNCTIONS=100_000
MAX_CALLS_PER_FUNCTION=20_000
MAX_TEXT_FIELD=1_000_000


def validate_ir_documents(*documents: dict) -> dict:
    errors=[]; warnings=[]; total=0; ids=set()
    if not documents: errors.append("no_documents")
    for di,doc in enumerate(documents):
        if not isinstance(doc,dict): errors.append(f"document_{di}:not_object"); continue
        functions=doc.get("functions",[])
        if not isinstance(functions,list): errors.append(f"document_{di}:functions_not_list"); continue
        total+=len(functions)
        for fi,fn in enumerate(functions):
            if not isinstance(fn,dict): errors.append(f"document_{di}:function_{fi}:not_object"); continue
            fid=str(fn.get("id") or "")
            if not fid: errors.append(f"document_{di}:function_{fi}:missing_id")
            elif fid in ids: errors.append(f"duplicate_function_id:{fid}")
            else: ids.add(fid)
            calls=fn.get("calls",[])
            if not isinstance(calls,list): errors.append(f"{fid or fi}:calls_not_list")
            elif len(calls)>MAX_CALLS_PER_FUNCTION: errors.append(f"{fid or fi}:too_many_calls")
            for key in ("name","file","language"):
                value=fn.get(key,"")
                if value is not None and len(str(value))>MAX_TEXT_FIELD: errors.append(f"{fid or fi}:{key}_too_large")
    if total>MAX_FUNCTIONS: errors.append("too_many_functions")
    if total==0 and not errors: warnings.append("empty_analysis")
    return {"passed":not errors,"function_count":total,"errors":errors,"warnings":warnings}


def require_valid_ir(*documents: dict) -> dict:
    result=validate_ir_documents(*documents)
    if not result["passed"]: raise ValueError("invalid analysis input: "+", ".join(result["errors"][:8]))
    return result
