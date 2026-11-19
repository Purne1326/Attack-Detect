"""Data formats passed between the pipeline stages (detection -> attribution -> policy -> secure alert)."""
from dataclasses import dataclass
from typing import List, Literal, Tuple


@dataclass
class Explanation:                       # made by step 05, read by steps 07-08
    flow_id: int
    score: float                         # autoencoder reconstruction error (mean over features)
    threshold: float                     # threshold t that was used
    is_anomaly: bool
    top_features: List[Tuple[str, float]]  # [(feature_name, z_score)] x top_k
    text: str                            # behaviour description used for ATT&CK retrieval
    true_label: str = ""                 # evaluation only; never read by retrieval or policy


@dataclass
class Technique:
    technique_id: str
    name: str
    similarity: float


@dataclass
class Decision:                          # made by step 08, read by step 11
    flow_id: int
    score: float
    techniques: List[Technique]
    action: Literal["ALLOW", "MONITOR", "BLOCK"]
    reason: str


@dataclass
class Alert:                             # signed + encrypted in step 11
    version: int
    alert_id: str
    counter: int
    timestamp: float
    decision: Decision
