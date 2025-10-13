from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .classes import KPXProtocolResponse


class ChangePublicKeysResponse(KPXProtocolResponse):
    action: str
    version: str
    publicKey: str
    success: Literal["true"]


class GetDatabasehashResponse(KPXProtocolResponse):
    hash: str
    version: str
    nonce: str
    success: Literal["true"]


class AssociateResponse(KPXProtocolResponse):
    hash: str
    version: str
    success: Literal["true"]
    id: str
    nonce: str


class TestAssociateResponse(KPXProtocolResponse):
    hash: str
    version: str
    success: Literal["true"]
    id: str
    nonce: str


class Login(BaseModel):
    group: str | None = None
    login: str
    name: str
    password: str
    uuid: str
    stringFields: list[str] = Field(default_factory=list)
    totp: str | None = None


class GetLoginsResponse(KPXProtocolResponse):
    count: int
    nonce: str
    success: Literal["true"]
    hash: str
    version: str
    entries: list[Login]

    # noinspection PyNestedDecorators
    @field_validator("count", mode="before")
    @classmethod
    def validate_count(cls, v: str | int) -> int:
        return int(v)


class Group(BaseModel):
    name: str
    uuid: str
    children: list['Group'] = Field(default_factory=list)


class Groups(BaseModel):
    groups: list[Group] = Field(default_factory=list)


class GetDatabaseGroupsResponse(KPXProtocolResponse):
    nonce: str
    success: Literal["true"]
    version: str
    defaultGroup: str | None = None
    defaultGroupAlwaysAllow: bool = None
    groups: Groups = Field(default_factory=dict)