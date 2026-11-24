"""
Core data models and graph primitives for SpecterGraph.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    ROOT_DOMAIN = "ROOT_DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    CNAME_RECORD = "CNAME_RECORD"
    CLOUD_SERVICE = "CLOUD_SERVICE"
    EXPOSURE = "EXPOSURE"
    TAKEOVER_RISK = "TAKEOVER_RISK"


class EdgeType(str, Enum):
    CONTAINS = "CONTAINS"
    RESOLVES_TO = "RESOLVES_TO"
    ALIAS_OF = "ALIAS_OF"
    HOSTED_ON = "HOSTED_ON"
    EXPOSES = "EXPOSES"
    VULNERABLE_TO = "VULNERABLE_TO"


class RiskLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AssetNode:
    id: str
    type: NodeType
    label: str
    risk: RiskLevel = RiskLevel.INFO
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class AssetEdge:
    source_id: str
    target_id: str
    relationship: EdgeType
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class TakeoverFinding:
    subdomain: str
    cname: str
    provider: str
    severity: RiskLevel
    evidence: str


@dataclass
class ExposureFinding:
    subdomain: str
    path: str
    url: str
    status_code: int
    severity: RiskLevel
    content_snippet: str
