from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class Event:
    timestamp: datetime
    source: str
    event_type: str
    src_ip: Optional[str] 
    username: Optional[str]
    raw: str
    
@dataclass
class Alert:
    timestamp: datetime
    rule: str
    severity: str
    src_ip: Optional[str]
    description: str
