ATTACK DETECTIVE WITH POST-QUANTUM SECURE ALERTS  -  one-person version
Full step-by-step guide: Attack_Detective_Complete_Guide_Windows.pdf

QUICK START (PowerShell, inside this folder)
  py -3.11 -m venv .venv
  .\.venv\Scripts\Activate.ps1
  pip install -r requirements.txt
  python scripts\00_check_setup.py          check libraries + post-quantum backend
  (download ATT&CK into data\attack\ - guide step 3)
  python run_all.py --demo                  test everything on synthetic data (~3-5 min)
  (download CICIDS2017 CSVs into data\raw\ - guide step 4)
  python run_all.py                         the real run (~1-2 h, mostly step 02)
  streamlit run dashboard\app.py            the demo dashboard

THE 12 STEPS (each can also be run alone:  python scripts\NN_name.py)
  00 check setup            06 build ATT&CK indexes
  01 prepare data           07 evaluate ATT&CK attribution
  02 train autoencoder      08 Allow/Monitor/Block policy
  03 Isolation Forest       09 security tests
  04 evaluate detection     10 post-quantum benchmark
  05 explanations           11 end-to-end secure delivery

Settings: config.yaml (only file you normally edit)
Results for the report: results\detection, results\attribution, results\pqc
Unit tests: pytest tests -q
