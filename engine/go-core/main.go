package main

import (
  "bufio"
  "encoding/json"
  "fmt"
  "net/url"
  "os"
  "sort"
  "strings"
  "sync"
)

type Item map[string]any
type Inventory struct { Endpoints []Item `json:"endpoints"`; HTTP []Item `json:"http"` }
type HostProfile struct { Host string `json:"host"`; EndpointCount int `json:"endpoint_count"`; Schemes []string `json:"schemes"`; ParameterNames []string `json:"parameter_names"` }

func sval(m Item, keys ...string) string { for _,k:=range keys { if v,ok:=m[k].(string); ok { return v } }; return "" }
func keys(m map[string]bool) []string { out:=make([]string,0,len(m)); for k:=range m { out=append(out,k) }; sort.Strings(out); return out }

func main(){
  path:="results/inventory.json"; if len(os.Args)>1 { path=os.Args[1] }
  f,err:=os.Open(path); if err!=nil { panic(err) }; defer f.Close()
  var inv Inventory; if err=json.NewDecoder(bufio.NewReader(f)).Decode(&inv); err!=nil { panic(err) }
  type partial struct{ host,scheme string; params []string }
  jobs:=make(chan Item); results:=make(chan partial); var wg sync.WaitGroup
  workers:=8
  for i:=0;i<workers;i++ { wg.Add(1); go func(){ defer wg.Done(); for item:=range jobs { raw:=sval(item,"value","url"); u,e:=url.Parse(raw); if e!=nil || u.Host=="" { continue }; ps:=[]string{}; for k:=range u.Query(){ ps=append(ps,k) }; results<-partial{strings.ToLower(u.Host),u.Scheme,ps} } }() }
  go func(){ for _,x:=range inv.Endpoints { jobs<-x }; close(jobs); wg.Wait(); close(results) }()
  type acc struct{ n int; schemes,params map[string]bool }; data:=map[string]*acc{}
  for r:=range results { a:=data[r.host]; if a==nil { a=&acc{schemes:map[string]bool{},params:map[string]bool{}}; data[r.host]=a }; a.n++; a.schemes[r.scheme]=true; for _,p:=range r.params { a.params[p]=true } }
  profiles:=[]HostProfile{}; for host,a:=range data { profiles=append(profiles,HostProfile{host,a.n,keys(a.schemes),keys(a.params)}) }; sort.Slice(profiles,func(i,j int)bool{return profiles[i].EndpointCount>profiles[j].EndpointCount})
  out:=map[string]any{"engine":"maher-go-core","workers":workers,"hosts":profiles,"endpoint_count":len(inv.Endpoints),"http_record_count":len(inv.HTTP)}
  b,_:=json.MarshalIndent(out,"","  "); fmt.Println(string(b))
}
