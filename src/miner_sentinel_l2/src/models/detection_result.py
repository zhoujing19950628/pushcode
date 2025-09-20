from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time


@dataclass
class DetectionResult:
    timestamp: float = field(default_factory=time.time)
    process_id: int = 0
    process_name: str = ""
    total_score: float = 0.0
    confidence: float = 0.0
    status: str = "NORMAL"  # NORMAL, SUSPICIOUS, CONFIRMED
    details: Dict[str, float] = field(default_factory=dict)
    evidences: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "process_id": self.process_id,
            "process_name": self.process_name,
            "total_score": round(self.total_score, 2),
            "confidence": round(self.confidence, 2),
            "status": self.status,
            "details": {k: round(v, 3) for k, v in self.details.items()},
            "evidences": self.evidences
        }
