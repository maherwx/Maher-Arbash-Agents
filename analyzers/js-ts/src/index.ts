import fs from 'node:fs';
import path from 'node:path';
import { parse } from '@babel/parser';
import traverseModule from '@babel/traverse';

const traverse: any = (traverseModule as any).default ?? traverseModule;
const root = process.argv[2];
if (!root) throw new Error('Usage: npm run analyze -- <js-or-ts-directory>');

const extensions = new Set(['.js','.jsx','.ts','.tsx','.mjs','.cjs']);
const ignored = new Set(['node_modules','.git','dist','build','coverage','.next']);
const files:string[] = [];

function walk(p:string){
  for(const e of fs.readdirSync(p,{withFileTypes:true})){
    const f=path.join(p,e.name);
    if(e.isDirectory() && !ignored.has(e.name)) walk(f);
    else if(e.isFile() && extensions.has(path.extname(f))) files.push(f);
  }
}
walk(root);

type Fn = {
  file:string; name:string; line:number|null; async:boolean; params:string[];
  calls:string[]; reads:string[]; writes:string[]; branches:number; loops:number;
  returns:number; throws:number; complexity:number;
};

const functions:Fn[]=[];
const callEdges=new Map<string,number>();
const imports=new Map<string,number>();
const routeHandlers:any[]=[];
const parseErrors:any[]=[];

function bump(map:Map<string,number>, key:string){ map.set(key,(map.get(key)||0)+1); }
function memberName(n:any):string {
  if(!n) return '';
  if(n.type==='Identifier') return n.name;
  if(n.type==='ThisExpression') return 'this';
  if(n.type==='Super') return 'super';
  if(n.type==='StringLiteral') return n.value;
  if(n.type==='MemberExpression' || n.type==='OptionalMemberExpression'){
    const left=memberName(n.object); const right=memberName(n.property);
    return left && right ? `${left}.${right}` : right || left;
  }
  return '';
}
function calleeName(n:any):string { return memberName(n); }
function paramName(n:any):string {
  if(!n) return '?';
  if(n.type==='Identifier') return n.name;
  if(n.type==='AssignmentPattern') return paramName(n.left);
  if(n.type==='RestElement') return '...'+paramName(n.argument);
  if(n.type==='ObjectPattern') return '{...}';
  if(n.type==='ArrayPattern') return '[...]';
  return n.type || '?';
}
function functionName(p:any):string {
  const n=p.node;
  if(n.id?.name) return n.id.name;
  const parent=p.parentPath?.node;
  if(parent?.type==='VariableDeclarator' && parent.id?.type==='Identifier') return parent.id.name;
  if(parent?.type==='ObjectProperty') return memberName(parent.key) || '<object-function>';
  if(parent?.type==='ClassMethod' || parent?.type==='ObjectMethod') return memberName(parent.key) || '<method>';
  return `<anonymous@${n.loc?.start?.line ?? 0}>`;
}
function isRouteCall(node:any): {method:string,path:string}|null {
  if(node?.type!=='CallExpression' && node?.type!=='OptionalCallExpression') return null;
  const name=calleeName(node.callee).toLowerCase();
  const method=['get','post','put','patch','delete','options','head'].find(m=>name.endsWith('.'+m));
  if(!method || !node.arguments?.length) return null;
  const first=node.arguments[0];
  if(first?.type==='StringLiteral') return {method:method.toUpperCase(),path:first.value};
  return null;
}

for(const file of files){
  const source=fs.readFileSync(file,'utf8');
  const rel=path.relative(root,file);
  let ast:any;
  try {
    ast=parse(source,{sourceType:'unambiguous',errorRecovery:true,plugins:['typescript','jsx','decorators-legacy','dynamicImport','classProperties','topLevelAwait']});
  } catch(e:any){ parseErrors.push({file:rel,error:String(e?.message||e)}); continue; }

  traverse(ast,{
    ImportDeclaration(p:any){ bump(imports,p.node.source.value); },
    CallExpression(p:any){
      const route=isRouteCall(p.node);
      if(route){
        const handler=p.node.arguments[p.node.arguments.length-1];
        routeHandlers.push({file:rel,line:p.node.loc?.start?.line??null,method:route.method,path:route.path,handler_type:handler?.type??null});
      }
    },
    Function(p:any){
      const n=p.node; const name=functionName(p); const calls=new Set<string>(); const reads=new Set<string>(); const writes=new Set<string>();
      let branches=0,loops=0,returns=0,throws=0;
      p.traverse({
        Function(inner:any){ if(inner.node!==n) inner.skip(); },
        CallExpression(cp:any){ const c=calleeName(cp.node.callee); if(c) calls.add(c); },
        OptionalCallExpression(cp:any){ const c=calleeName(cp.node.callee); if(c) calls.add(c); },
        Identifier(ip:any){
          if(ip.isReferencedIdentifier()) reads.add(ip.node.name);
          if(ip.parentPath?.isAssignmentExpression() && ip.parentKey==='left') writes.add(ip.node.name);
          if(ip.parentPath?.isUpdateExpression()) writes.add(ip.node.name);
        },
        IfStatement(){ branches++; }, ConditionalExpression(){ branches++; }, SwitchCase(){ branches++; },
        ForStatement(){ loops++; }, ForInStatement(){ loops++; }, ForOfStatement(){ loops++; }, WhileStatement(){ loops++; }, DoWhileStatement(){ loops++; },
        ReturnStatement(){ returns++; }, ThrowStatement(){ throws++; }, CatchClause(){ branches++; }
      });
      const caller=`${rel}:${name}`;
      for(const c of calls) bump(callEdges,`${caller}\u0000${c}`);
      functions.push({file:rel,name,line:n.loc?.start?.line??null,async:!!n.async,params:(n.params||[]).map(paramName),calls:[...calls].sort(),reads:[...reads].sort(),writes:[...writes].sort(),branches,loops,returns,throws,complexity:1+branches+loops+throws});
    }
  });
}

const output={
  schema_version:'2.0', engine:'maher-js-analyzer/babel-ast', files:files.length,
  function_count:functions.length, imports:Object.fromEntries([...imports.entries()].sort((a,b)=>b[1]-a[1])),
  functions:functions.sort((a,b)=>b.complexity-a.complexity || a.file.localeCompare(b.file) || (a.line||0)-(b.line||0)),
  route_handlers:routeHandlers,
  call_edges:[...callEdges.entries()].map(([key,count])=>{const [caller,callee]=key.split('\u0000');return {caller,callee,count};}).sort((a,b)=>b.count-a.count),
  parse_errors:parseErrors
};
console.log(JSON.stringify(output,null,2));
