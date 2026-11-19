"""Feature -> behaviour phrases (value higher than normal, value lower than normal).

RULE: describe network behaviour only. Never write attack names (no 'DoS', 'PortScan',
'brute force', 'botnet'...), otherwise the ATT&CK retrieval would be leaking labels.
"""

FEATURE_PHRASES = {
    "Flow Duration": ("unusually long-lived connection", "very short connection"),
    "Total Fwd Packets": ("many packets sent by the client", "very few packets sent by the client"),
    "Total Backward Packets": ("many packets returned by the server",
        "few or no replies from the server"),
    "Total Length of Fwd Packets": ("large volume of data sent by the client",
        "almost no data sent by the client"),
    "Total Length of Bwd Packets": ("large volume of data returned by the server",
        "almost no data returned by the server"),
    "Fwd Packet Length Max": ("very large client packets", "only small client packets"),
    "Fwd Packet Length Mean": ("large client requests", "small or empty client requests"),
    "Bwd Packet Length Max": ("very large server packets", "only small server packets"),
    "Bwd Packet Length Mean": ("large server responses", "small or empty server responses"),
    "Flow Bytes/s": ("very high byte rate", "very low byte rate"),
    "Flow Packets/s": ("very high packet rate", "very low packet rate"),
    "Fwd Packets/s": ("client sends packets at a very high rate",
        "client sends packets very slowly"),
    "Bwd Packets/s": ("server replies at a very high rate", "server replies very slowly"),
    "Flow IAT Mean": ("long gaps between packets, slow trickle of traffic",
        "packets sent in rapid succession"),
    "Flow IAT Max": ("very long pause inside the connection", "no pauses inside the connection"),
    "Flow IAT Min": ("packets never sent close together", "back-to-back packets"),
    "Fwd IAT Total": ("client keeps the connection open for a long time",
        "client activity is very brief"),
    "Fwd IAT Mean": ("client sends packets with long delays", "client sends packets very quickly"),
    "Bwd IAT Mean": ("server answers with long delays", "server answers very quickly"),
    "Active Mean": ("long bursts of activity", "very short bursts of activity"),
    "Idle Mean": ("long idle periods while the connection is held open", "no idle periods"),
    "Idle Max": ("very long idle period on an open connection", "no long idle periods"),
    "FIN Flag Count": ("many connection-closing (FIN) packets", "connections not closed normally"),
    "SYN Flag Count": ("many connection-opening (SYN) packets, repeated connection attempts",
        "no connection set-up packets"),
    "RST Flag Count": ("connection resets, refused or aborted connections", "no connection resets"),
    "PSH Flag Count": ("many pushed data packets", "few pushed data packets"),
    "ACK Flag Count": ("many acknowledgement packets",
        "few acknowledgements, incomplete handshakes"),
    "URG Flag Count": ("urgent flag set, unusual TCP flags", "urgent flag absent"),
    "Fwd PSH Flags": ("client pushes data immediately", "client never pushes data"),
    "Down/Up Ratio": ("much more data downloaded than uploaded",
        "much more data uploaded than downloaded"),
    "Average Packet Size": ("large average packet size", "small average packet size"),
    "Packet Length Mean": ("large packets", "small packets"),
    "Packet Length Std": ("highly variable packet sizes", "identical, uniform packet sizes"),
    "Packet Length Variance": ("highly variable packet sizes", "identical, uniform packet sizes"),
    "Max Packet Length": ("very large maximum packet size", "small maximum packet size"),
    "Min Packet Length": ("large minimum packet size", "tiny minimum packet size"),
    "Fwd Header Length": ("large client header overhead, many packets",
        "small client header overhead"),
    "Bwd Header Length": ("large server header overhead", "small server header overhead"),
    "Init_Win_bytes_forward": ("unusually large initial TCP window from client",
        "unusually small initial TCP window from client"),
    "Init_Win_bytes_backward": ("unusually large initial TCP window from server",
        "unusually small or missing TCP window from server"),
    "act_data_pkt_fwd": ("many client packets carrying payload", "client packets carry no payload"),
    "min_seg_size_forward": ("large minimum segment size", "small minimum segment size"),
    "Subflow Fwd Bytes": ("large client data per subflow", "little client data per subflow"),
    "Subflow Bwd Bytes": ("large server data per subflow", "little server data per subflow"),
}


def phrase(feature: str, higher: bool) -> str:
    if feature in FEATURE_PHRASES:
        hi, lo = FEATURE_PHRASES[feature]
        return hi if higher else lo
    return f"unusual {feature} ({'higher' if higher else 'lower'} than normal)"
