"""Step 06: load MITRE ATT&CK and build the four retrieval indexes (TF-IDF / MiniLM x plain / enriched)."""
from common import Dirs, banner, load_cfg, need, save_json
from attack_detective.attribution.keywords import KEYWORDS
from attack_detective.attribution.retrieve import Retriever
from attack_detective.attribution.stix_loader import load_techniques


def main():
    banner("Step 06 - build ATT&CK indexes")
    cfg = load_cfg()
    d = Dirs(cfg)
    need(d.stix, "the ATT&CK download (guide step 3)")
    techs = load_techniques(d.stix)
    n_sub = sum(t.is_subtechnique for t in techs)
    print(f"Loaded {len(techs)} active techniques ({len(techs) - n_sub} techniques, {n_sub} sub-techniques)")
    missing = [k for k in KEYWORDS if k not in {t.technique_id for t in techs}]
    if missing:
        print("  WARNING: keyword IDs not in this ATT&CK version:", missing)
    save_json([t.__dict__ for t in techs], d.art_att / "techniques.json")
    for method in ("tfidf", "minilm"):
        for enriched in (False, True):
            name = f"{method}_{'enriched' if enriched else 'plain'}"
            try:
                r = Retriever(techs, method, enriched)
            except Exception as e:                    # e.g. MiniLM model cannot be downloaded
                print(f"  SKIPPED {name}: {type(e).__name__}: {str(e)[:120]}")
                continue
            r.save(d.art_att / f"index_{name}.pkl")
            ex = r.attribute("many connection attempts to many ports with no replies")[0]
            print(f"  built {name:<16} example top-1: {ex.technique_id} {ex.name} ({ex.similarity})")


if __name__ == "__main__":
    main()
