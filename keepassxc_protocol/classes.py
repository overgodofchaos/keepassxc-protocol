import os

from pydantic import BaseModel, ConfigDict

debug = True if os.environ.get("KPX_PROTOCOL_DEBUG") else False


class KPXProtocol(BaseModel):
    model_config = ConfigDict(
        validate_assignment=True,
        arbitrary_types_allowed=True,
    )




