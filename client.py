"""Bug Hunter Environment Client."""

from typing import Dict, Optional

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from models import BugHunterAction, BugHunterObservation


class BugHunterEnv(
    EnvClient[BugHunterAction, BugHunterObservation, State]
):

    def _step_payload(self, action: BugHunterAction) -> Dict:
        payload = {
            "method": action.method,
            "path": action.path,
        }
        if action.body is not None:
            payload["body"] = action.body
        return payload

    def _parse_result(self, payload: Dict) -> StepResult[BugHunterObservation]:
        obs_data = payload.get("observation", {})
        observation = BugHunterObservation(
            status_code=obs_data.get("status_code", 404),
            body=obs_data.get("body", ""),
            hint=obs_data.get("hint", ""),
            done=payload.get("done", False),
            reward=payload.get("reward"),
            metadata=obs_data.get("metadata", {}),
        )

        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
