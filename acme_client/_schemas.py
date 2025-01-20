from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class Error(BaseModel):
    e_type: str = Field(alias="type")
    detail: str


class Identifier(BaseModel):
    i_type: str = Field(alias="type")
    value: str


class LetsencryptOrder(BaseModel):
    status: str
    expires: datetime
    identifiers: list[Identifier]
    authorizations: list[str]
    finalize: str
    certificate: Optional[str] = None


class Challenge(BaseModel):
    ch_type: str = Field(alias="type")
    status: str
    url: str
    token: str
    error: Optional[Error] = None


class Challenges(BaseModel):
    identifier: Identifier
    status: str
    expires: datetime
    challenges: list[Challenge]

    def _find_challenge(self, ch_type: str) -> Challenge:
        challenge = [ch for ch in self.challenges if ch.ch_type == ch_type]
        if len(challenge) != 1:
            raise ValueError(f"not found '{ch_type}' challenge")
        return challenge[0]

    @property
    def dns_01_challenge(self) -> Challenge:
        return self._find_challenge("dns-01")

    @property
    def http_01_challenge(self) -> Challenge:
        return self._find_challenge("http-01")
