import argparse
from .orchestrator import run
def main():
    p=argparse.ArgumentParser(prog="maher-bounty")
    s=p.add_subparsers(dest="cmd",required=True)
    r=s.add_parser("run"); r.add_argument("--scope",required=True); r.add_argument("--rules",required=True); r.add_argument("--out",default="reports")
    a=p.parse_args()
    if a.cmd=="run":
        result=run(a.scope,a.rules,a.out)
        print(f"Completed {result['agent_count']} agent passes. Reports: {a.out}")
if __name__=="__main__": main()
