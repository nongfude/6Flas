import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def main():
    ap = argparse.ArgumentParser(description='Build/run 6FLAS research artifact')
    for flag in ['all', 'tests', 'benchmark', 'model']:
        ap.add_argument('--'+flag, action='store_true')
    ap.add_argument('--cc', default='gcc')
    ap.add_argument('--output', default='results/local')
    a = ap.parse_args()
    if not (a.all or a.tests or a.benchmark or a.model):
        ap.error('select --all, --tests, --benchmark, or --model')
    out = (ROOT/a.output).resolve(); out.mkdir(parents=True, exist_ok=True)
    build = ROOT/'build'; build.mkdir(exist_ok=True)
    def run(cmd, name, env=None):
        print('+', ' '.join(map(str,cmd)), flush=True)
        p = subprocess.run(list(map(str,cmd)), cwd=ROOT, env=env,
                           capture_output=True, text=True)
        (out/(name+'.stdout.txt')).write_text(p.stdout, encoding='utf-8')
        (out/(name+'.stderr.txt')).write_text(p.stderr, encoding='utf-8')
        if p.returncode: raise RuntimeError(name+' failed: '+p.stderr+p.stdout)
        return p.stdout
    compiler = None
    if a.all or a.tests or a.benchmark:
        compiler = run([a.cc,'--version'], 'compiler').splitlines()[0]
    info = dict(platform=platform.platform(), machine=platform.machine(),
                python=sys.version, compiler=compiler,
                flags=['-O3','-Wall','-Wextra','-std=c11','-Wno-unused-function'])
    try: info['matplotlib'] = importlib.metadata.version('matplotlib')
    except importlib.metadata.PackageNotFoundError: info['matplotlib'] = None
    (out/'environment.json').write_text(json.dumps(info,indent=2), encoding='utf-8')
    suffix = '.exe' if os.name=='nt' else ''
    for selected,src,name in [(a.all or a.tests,'negative_tests','negative_tests'),
                              (a.all or a.benchmark,'bench_flas','benchmark')]:
        if not selected: continue
        exe = build/(src+suffix)
        cmd = [a.cc,'-O3','-Wall','-Wextra','-std=c11','-Wno-unused-function',
               ROOT/'proto'/(src+'.c'),'-o',exe]
        if src=='bench_flas': cmd.append('-lm')
        run(cmd,name+'_build'); text=run([exe],name)
        if src=='bench_flas':
            data=json.loads(text)
            (out/'benchmark.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
        elif 'ALL EXPECTATIONS HOLD (0 failures)' not in text:
            raise RuntimeError('Protocol test success marker missing')
    if a.all or a.model:
        env=os.environ.copy();env['FLAS_OUT']=str(out/'model')
        run([sys.executable,ROOT/'eval/flas_model.py'],'model',env)
    print('Completed. Results:',out)

if __name__=='__main__': main()
