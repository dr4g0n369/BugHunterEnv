from typing import Optional
from openenv.core.env_server.types import Action, Observation
from pydantic import Field

class BugHunterAction(Action):
    method: str = Field(..., description="HTTP Method (GET, POST)")
    path: str = Field(..., description="URL path (e.g. /api/users)")
    body: Optional[str] = Field(default=None, description="Request body for POST requests (JSON string)")

class BugHunterObservation(Observation):
    status_code: int = Field(..., description="HTTP Status Code")
    body: str = Field(..., description="HTTP Response Body")
    hint: str = Field(default="", description="Contextual hint for partial progress")
