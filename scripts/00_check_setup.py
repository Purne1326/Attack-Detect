"""Step 00: check Python libraries, the post-quantum backend and the data files."""
import importlib
import platform

from common import DEMO, Dirs, banner, load_cfg


def main():
    banner("Step 00 - check setup")
    cfg = load_cfg()
    d = Dirs(cfg)
    print("Python", platform.python_version(), "|", platform.system(), platform.release(),
          "|", platform.processor() or platform.machine())
    ok = True
    for mod in ("numpy", "pandas", "sklearn", "torch", "yaml", "cryptography", "streamlit",
                "sentence_transformers", "matplotlib"):
        try:
            m = importlib.import_module(mod)
            print(f"  [OK]   {mod:<22} {getattr(m, '__version__', '')}")
        except Exception as e:
            ok = False
            print(f"  [FAIL] {mod:<22} {type(e).__name__}: {e}")

    from attack_detective.pqc.backend import PQCUnavailable, load_pq
    try:
        kem, sig = load_pq(cfg["pqc"]["backend"], cfg["pqc"]["allow_pure_python"])
        pk, sk = kem.keygen()
        ct, ss = kem.encaps(pk)
        spk, ssk = sig.keygen()
        s = sig.sign(ssk, b"test")
        good = kem.decaps(sk, ct) == ss and sig.verify(spk, b"test", s)
        print(f"  [{'OK' if good else 'FAIL'}]   post-quantum backend   {kem.backend}: "
              f"ML-KEM-768 ciphertext {len(ct)} B, ML-DSA-65 signature {len(s)} B")
        ok &= good
    except PQCUnavailable as e:
        ok = False
        print("  [FAIL] post-quantum backend  ", e)
        print("         -> see the guide: Troubleshooting, 'no post-quantum backend'")

    csvs = sorted(d.raw.glob("*.csv"))
    print(f"  [{'OK' if csvs else '--'}]   dataset CSVs in {d.raw.relative_to(d.raw.parents[1])}: {len(csvs)} files"
          + ("" if csvs else "   (download CICIDS2017 - or run: python run_all.py --demo)"))
    has_stix = d.stix.exists()
    print(f"  [{'OK' if has_stix else '--'}]   ATT&CK file: {'found' if has_stix else 'missing (download it - guide step 3)'}")
    print("\nSETUP OK" if ok else "\nFix the [FAIL] lines above before continuing.")
    if DEMO and not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
