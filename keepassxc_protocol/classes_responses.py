from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .classes import KPXProtocol


class BaseResponse(KPXProtocol):
    pass


class ChangePublicKeysResponse(BaseResponse):
    action: str
    version: str
    publicKey: str
    success: Literal["true"]


class GetDatabasehashResponse(BaseResponse):
    hash: str
    version: str
    nonce: str
    success: Literal["true"]


class AssociateResponse(BaseResponse):
    hash: str
    version: str
    success: Literal["true"]
    id: str
    nonce: str


class TestAssociateResponse(BaseResponse):
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


class GetLoginsResponse(BaseResponse):
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


class GetDatabaseGroupsResponse(BaseResponse):
    nonce: str
    success: Literal["true"]
    version: str
    defaultGroup: str | None = None
    defaultGroupAlwaysAllow: bool = None
    groups: Groups = Field(default_factory=dict)