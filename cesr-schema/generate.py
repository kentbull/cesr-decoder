import json
from os import (path)

from keri.core.coring import (
    Matter,
    TextCodex
)
from keri.core.counting import (
    Counter, CounterCodex_1_0, CounterCodex_2_0, SealCodex_2_0, GenusCodex,
)
from keri.core.indexing import (
    Indexer,
    IndexerCodex,
    IndexedSigCodex,
    IndexedCurrentSigCodex,
    IndexedBothSigCodex,
)
from keri.core.coring import (
    MatterCodex,
    SmallVarRawSizeCodex,
    LargeVarRawSizeCodex,
    NonTransCodex,
    DigCodex,
    NumCodex, BextCodex, PreCodex,
)
from keri.core.signing import (
    CipherX25519FixQB64Codex,
    CipherX25519VarQB64Codex,
    CipherX25519VarStrmCodex,
    CipherX25519AllQB64Codex,
    CipherX25519QB2VarCodex,
    CipherX25519AllVarCodex, CipherX25519AllCodex,
)
from keri.kering import ColdCodex

# from keri.core.parsing import (ColdCodex)

# names.json

names = set()
for i in (
        # keri.core.parsing
        ColdCodex,
        # keri.core.coring
        MatterCodex,
        SmallVarRawSizeCodex,
        LargeVarRawSizeCodex,
        NonTransCodex,
        DigCodex,
        NumCodex,
        BextCodex,
        TextCodex,
        CipherX25519VarStrmCodex,
        CipherX25519FixQB64Codex,
        CipherX25519VarQB64Codex,
        CipherX25519AllQB64Codex,
        CipherX25519QB2VarCodex,
        CipherX25519AllVarCodex,
        CipherX25519AllCodex,
        PreCodex,
        IndexerCodex,
        IndexedSigCodex,
        IndexedCurrentSigCodex,
        IndexedBothSigCodex,
        CounterCodex_1_0,
        CounterCodex_2_0,
        SealCodex_2_0,
        GenusCodex
):
    for key, value in i().__dict__.items():
        names.add(key)

with open("names.json", "w") as fp:
    json.dump(sorted(names), fp, indent=2)

# codex.json

special = {}
codes = set()
codex = {}
for i in (
        # keri.core.parsing
        ColdCodex,
        # keri.core.coring
        MatterCodex,
        SmallVarRawSizeCodex,
        LargeVarRawSizeCodex,
        NonTransCodex,
        DigCodex,
        NumCodex,
        BextCodex,
        TextCodex,
        CipherX25519VarStrmCodex,
        CipherX25519FixQB64Codex,
        CipherX25519VarQB64Codex,
        CipherX25519AllQB64Codex,
        CipherX25519QB2VarCodex,
        CipherX25519AllVarCodex,
        CipherX25519AllCodex,
        PreCodex,
        IndexerCodex,
        IndexedSigCodex,
        IndexedCurrentSigCodex,
        IndexedBothSigCodex,
        CounterCodex_1_0,
        CounterCodex_2_0,
        SealCodex_2_0,
        GenusCodex
):
    o = {}
    for key, value in i().__dict__.items():
        if not value in o:
            o[value] = key
        codes.add(value)
        assert key in names, f"key = {i.__name__}.{key}"
    name = i.__name__.replace("Codex", "")
    codex[name] = o

with open("codex.json", "w") as fp:
    json.dump(codex, fp, indent=2)

# sizes.json
# TODO pull sizes for Indexer in an Indexer specific way to get os instead of xs
# TODO pull sizes for Counter in a Counter specific way to get the decoupled sizes from the major and minor KERI versions object
sizes = {}
for i in (Matter, Indexer, Counter):
    o = {}
    for key, value in i.Sizes.items():
        assert key in codes, f"key = {i.__name__}.{key}"
        # TODO change pull of Counter codes to reflect new Cizage structure for KERI 1.0 and 2.0
        o[key] = value._asdict()
    sizes[i.__name__] = o

with open("sizes.json", "w") as fp:
    json.dump(sizes, fp, indent=2)

# hards.json
hards = {}
for i in (Matter, Indexer, Counter):
    o = {}
    for key, value in i.Hards.items():
        assert key in codes, f"key = {i.__name__}.{key}"
        o[key] = value._asdict()
    hards[i.__name__] = o
with open("hards.json", "w") as fp:
    json.dump(hards, fp, indent=2)

# counter.json

if path.isfile("counter.json"):
    with open("counter.json", "r") as fp:
        counter = json.load(fp)
else:
    counter = {}

for i in ("Counter", "AltCounter"):
    if not i in counter:
        counter[i] = {}
    for key, value in codex[i].items():
        if not key in counter[i]:
            counter[i][key] = {}
        counter[i][key]["name"] = value

with open("counter.json", "w") as fp:
    json.dump(counter, fp, indent=2)
