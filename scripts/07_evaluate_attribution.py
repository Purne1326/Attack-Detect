"""Step 07: top-1 / top-3 ATT&CK accuracy for every index + random baseline; writes attributions.jsonl."""
import numpy as np
import pandas as pd

from common import Dirs, banner, load_cfg, need
from attack_detective.attribution.label_map import accepted, is_correct
from attack_detective.attribution.retrieve import Retriever
from attack_detective.contracts.io import read_jsonl, write_jsonl


def main():
    banner("Step 07 - evaluate ATT&CK attribution")
    cfg = load_cfg()
    a, d = cfg["attribution"], Dirs(cfg)
    need(d.art_det / "explanations.jsonl", "step 05 (05_explain.py)")
    need(d.art_att / "index_tfidf_plain.pkl", "step 06 (06_build_attack_index.py)")
    expl = read_jsonl(d.art_det / "explanations.jsonl")
    # labels are used HERE ONLY, to score the result - never by the retrieval itself
    ev = [e for e in expl if e["is_anomaly"] and accepted(e["true_label"])]
    print(f"{len(expl):,} explanations; evaluating on {len(ev):,} flagged attack flows with a mapped label")
    k = a["top_k"]
    rows, fam_rows = [], []
    labels = np.array([e["true_label"] for e in ev])
    for idx_file in sorted(d.art_att.glob("index_*.pkl")):
        name = idx_file.stem.replace("index_", "")
        preds = Retriever.load(idx_file).attribute_many([e["text"] for e in ev], k)
        top1 = np.array([is_correct(p[0].technique_id, e["true_label"]) for p, e in zip(preds, ev)])
        topk = np.array([any(is_correct(t.technique_id, e["true_label"]) for t in p) for p, e in zip(preds, ev)])
        rows.append({"config": name, "n": len(ev), "top1": top1.mean(), f"top{k}": topk.mean()})
        for lab in np.unique(labels):
            m = labels == lab
            fam_rows.append({"config": name, "label": lab, "n": int(m.sum()),
                             "top1": top1[m].mean(), f"top{k}": topk[m].mean()})

    techs = Retriever.load(d.art_att / "index_tfidf_plain.pkl").techniques
    rng = np.random.default_rng(0)
    r1, rk = [], []
    for _ in range(a["random_baseline_runs"]):
        picks = [rng.choice(len(techs), k, replace=False) for _ in ev]
        r1.append(np.mean([is_correct(techs[p[0]].technique_id, e["true_label"]) for p, e in zip(picks, ev)]))
        rk.append(np.mean([any(is_correct(techs[j].technique_id, e["true_label"]) for j in p)
                           for p, e in zip(picks, ev)]))
    rows.append({"config": "random", "n": len(ev), "top1": np.mean(r1), f"top{k}": np.mean(rk)})

    df = pd.DataFrame(rows).round(4)
    df.to_csv(d.res_att / "attribution_topk.csv", index=False)
    pd.DataFrame(fam_rows).round(4).to_csv(d.res_att / "attribution_per_family.csv", index=False)
    print(df.to_string(index=False))

    main_name = f"{a['main_method']}_{'enriched' if a['main_enriched'] else 'plain'}"
    need(d.art_att / f"index_{main_name}.pkl", f"step 06 (index '{main_name}' - check config.yaml)")
    preds = Retriever.load(d.art_att / f"index_{main_name}.pkl").attribute_many([e["text"] for e in expl], k)
    out = [{"flow_id": e["flow_id"], "techniques": [t.__dict__ for t in p]} for e, p in zip(expl, preds)]
    n = write_jsonl(out, d.art_att / "attributions.jsonl")
    print(f"Wrote {n:,} attributions using '{main_name}' -> {d.art_att / 'attributions.jsonl'}")


if __name__ == "__main__":
    main()
