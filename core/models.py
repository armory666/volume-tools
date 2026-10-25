from dataclasses import dataclass, field

@dataclass
class Hit:
    source: str
    kind: str
    value: str
    meta: dict = field(default_factory=dict)
