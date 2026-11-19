"""Plain fully-connected autoencoder: d -> 64 -> 32 -> 16 -> 32 -> 64 -> d."""
import torch
from torch import nn


class AutoEncoder(nn.Module):
    def __init__(self, n_features: int, hidden=(64, 32, 16)):
        super().__init__()
        enc, prev = [], n_features
        for h in hidden:
            enc += [nn.Linear(prev, h), nn.ReLU()]
            prev = h
        dec = []
        for h in reversed(hidden[:-1]):
            dec += [nn.Linear(prev, h), nn.ReLU()]
            prev = h
        dec.append(nn.Linear(prev, n_features))   # linear output: inputs are standardised
        self.encoder = nn.Sequential(*enc)
        self.decoder = nn.Sequential(*dec)
        self.n_features = n_features
        self.hidden = tuple(hidden)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


def save_model(model: AutoEncoder, path):
    torch.save({"state": model.state_dict(), "n_features": model.n_features,
                "hidden": model.hidden}, path)


def load_model(path) -> AutoEncoder:
    ck = torch.load(path, map_location="cpu")
    m = AutoEncoder(ck["n_features"], ck["hidden"])
    m.load_state_dict(ck["state"])
    m.eval()
    return m
