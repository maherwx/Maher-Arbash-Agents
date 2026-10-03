import fs from 'node:fs';
import path from 'node:path';
import { parse } from '@babel/parser';

const root = process.argv[2];
if (!root) throw new Error('Usage: npm run analyze -- <js-or-ts-directory>');
const extensions = new Set(['.js','.jsx','.ts','.tsx','.mjs','.cjs']);
const files:string[] = [];
function walk(p:string){ for(const e of fs.readdirSync(p,{withFileTypes:true})){ const f=path.join(p,e.name); if(e.isDirectory() && e.name!=='node_modules') walk(f); else if(e.isFile() && extensions.has(path.extname(f))) files.push(f); } }
walk(root);

const urls = new Set<string>();
const routeHints = new Set<string>();
const envRefs = new Set<string>();
for(const file of files){
  const source=fs.readFileSync(file,'utf8');
  try { parse(source,{sourceType:'unambiguous',plugins:['typescript','jsx','decorators-legacy','dynamicImport']}); } catch {}
  for(const m of source.matchAll(/https?:\/\/[^\s"'`<>]+/g)) urls.add(m[0]);
  for(const m of source.matchAll(/["'`]((?:\/api\/|\/graphql|\/oauth|\/auth\/|\/v\d+\/)[^"'`\s]*)["'`]/g)) routeHints.add(m[1]);
  for(const m of source.matchAll(/(?:process\.env\.|import\.meta\.env\.)([A-Z0-9_]+)/g)) envRefs.add(m[1]);
}
console.log(JSON.stringify({engine:'maher-js-analyzer/typescript',files:files.length,absolute_urls:[...urls].sort(),route_hints:[...routeHints].sort(),environment_references:[...envRefs].sort()},null,2));
