"""Run every step in order.

  python run_all.py                 all steps on the real data (data/raw)
  python run_all.py --demo          quick test on synthetic data (separate *_demo folders)
  python run_all.py --from 6        start at step 06 (earlier outputs must exist)
  python run_all.py --only 4        run a single step
"""
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STEPS = sorted(p for p in (ROOT / "scripts").glob("[0-9][0-9]_*.py"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true", help="synthetic data, fast settings, *_demo folders")
    ap.add_argument("--from", dest="start", type=int, default=0)
    ap.add_argument("--only", type=int, default=None)
    args = ap.parse_args()
    env = dict(os.environ, PYTHONIOENCODING="utf-8")      # safe printing on any Windows console
    if args.demo:
        env["AD_DEMO"] = "1"
        demo_raw = ROOT / "data" / "raw_demo"
        if not list(demo_raw.glob("*.csv")):
            print("Creating synthetic demo data in data/raw_demo ...")
            subprocess.run([sys.executable, str(ROOT / "tools" / "make_demo_data.py"), str(demo_raw)], check=True)
    steps = [s for s in STEPS if (args.only is None and int(s.name[:2]) >= args.start)
             or int(s.name[:2]) == args.only]
    t_all = time.time()
    for s in steps:
        t = time.time()
        r = subprocess.run([sys.executable, str(s)], env=env, cwd=ROOT)
        if r.returncode != 0:
            sys.exit(f"\nSTOPPED at {s.name} (fix the message above, then: python run_all.py --from {s.name[:2]}"
                     f"{' --demo' if args.demo else ''})")
        print(f"--- {s.name} finished in {time.time() - t:.0f}s")
    print(f"\nALL DONE in {(time.time() - t_all) / 60:.1f} min.  Dashboard:  "
          + ("$env:AD_DEMO=1; " if args.demo else "") + "streamlit run dashboard\\app.py")


if __name__ == "__main__":
    main()
