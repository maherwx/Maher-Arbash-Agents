from __future__ import annotations

import hashlib
import re
from pathlib import Path


def _id(language: str, file: str, symbol: str, line: int) -> str:
    raw=f"{language}\0{file}\0{symbol}\0{line}"
    return "fn:"+hashlib.sha256(raw.encode()).hexdigest()[:20]

JAVA_METHOD=re.compile(r"(?P<mods>(?:public|private|protected|static|final|synchronized|abstract|native|\s)+)?(?P<ret>[\w<>\[\],.?]+)\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)\s*(?:throws\s+[^\{]+)?\{")
CS_METHOD=re.compile(r"(?P<mods>(?:public|private|protected|internal|static|virtual|override|async|sealed|abstract|partial|\s)+)?(?P<ret>[\w<>\[\],.?]+)\s+(?P<name>[A-Za-z_][\w]*)\s*\((?P<params>[^)]*)\)\s*\{")
CALL=re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
ROUTE_JAVA=re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)",re.I)
ROUTE_CS=re.compile(r"\[(HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete)(?:\s*\(\s*[\"']([^\"']*)[\"'])?",re.I)


def _params(raw: str) -> list[str]:
    out=[]
    for item in raw.split(','):
        item=item.strip()
        if not item: continue
        bits=re.sub(r"@[A-Za-z_$][\w$]*(?:\([^)]*\))?","",item).split()
        if bits: out.append(bits[-1].replace("...",""))
    return out


def _scan(root: str|Path, language: str) -> dict:
    root=Path(root); ext=".java" if language=="java" else ".cs"; method_re=JAVA_METHOD if language=="java" else CS_METHOD
    functions=[]; routes=[]; parse_errors=[]
    for path in root.rglob(f"*{ext}"):
        if any(p in {".git","target","build","bin","obj","vendor"} for p in path.parts): continue
        try: text=path.read_text(encoding="utf-8",errors="ignore")
        except OSError as exc:
            parse_errors.append({"file":str(path),"error":str(exc)}); continue
        rel=str(path.relative_to(root)); lines=text.splitlines()
        for i,line in enumerate(lines,1):
            rm=(ROUTE_JAVA if language=="java" else ROUTE_CS).search(line)
            if rm:
                routes.append({"file":rel,"line":i,"method":rm.group(1).replace("Mapping","").replace("Http","").upper(),"path":rm.group(2) or ""})
            m=method_re.search(line)
            if not m: continue
            name=m.group("name"); params=_params(m.group("params")); depth=line.count("{")-line.count("}"); body=[line]; j=i
            while depth>0 and j<len(lines):
                body.append(lines[j]); depth+=lines[j].count("{")-lines[j].count("}"); j+=1
            body_text="\n".join(body)
            calls=sorted({x.split('.')[-1] for x in CALL.findall(body_text) if x.split('.')[-1] != name})
            branches=len(re.findall(r"\b(?:if|switch|case|catch)\b",body_text)); loops=len(re.findall(r"\b(?:for|while|foreach)\b",body_text)); throws=len(re.findall(r"\bthrow\b",body_text))
            nearby=[r for r in routes if r["file"]==rel and 0 <= i-r["line"] <= 5]
            functions.append({
                "id":_id(language,rel,name,i),"language":language,"file":rel,"name":name,"line":i,
                "async_function": bool(language=="csharp" and re.search(r"\basync\b",m.group("mods") or "")),
                "parameters":params,"calls":calls,"reads":[],"writes":[],
                "complexity":1+branches+loops+throws,"route_bindings":nearby,
            })
    return {"schema_version":"1.0","language":language,"function_count":len(functions),"functions":functions,"routes":routes,"parse_errors":parse_errors}


def analyze_java(root: str|Path) -> dict:
    return _scan(root,"java")


def analyze_csharp(root: str|Path) -> dict:
    return _scan(root,"csharp")
