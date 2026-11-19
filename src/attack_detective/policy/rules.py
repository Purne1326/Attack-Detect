"""Transparent Allow / Monitor / Block policy. Every threshold is documented in policy.yaml.

ALLOW   if score < t                       (not anomalous)
BLOCK   if score >= high_multiplier * t    (strongly anomalous)
        and top-1 similarity >= s_min      (and we know roughly what it is)
MONITOR otherwise                          (anomalous but uncertain -> log and watch)
"""
from typing import List

from attack_detective.contracts.schemas import Decision, Technique


def decide(expl: dict, techniques: List[Technique], cfg: dict) -> Decision:
    score, t = float(expl["score"]), float(expl["threshold"])
    t_high = cfg["high_multiplier"] * t
    top_sim = techniques[0].similarity if techniques else 0.0
    top_id = techniques[0].technique_id if techniques else "-"
    if score < t:
        action, reason = "ALLOW", f"score {score:.3g} < threshold {t:.3g}"
    elif score >= t_high and top_sim >= cfg["s_min"]:
        action, reason = "BLOCK", (f"score {score:.3g} >= {cfg['high_multiplier']}x threshold and "
                                   f"{top_id} similarity {top_sim:.2f} >= {cfg['s_min']}")
    else:
        why = "score below high threshold" if score < t_high else f"low similarity {top_sim:.2f}"
        action, reason = "MONITOR", f"anomalous ({why})"
    return Decision(flow_id=int(expl["flow_id"]), score=score, techniques=techniques,
                    action=action, reason=reason)
