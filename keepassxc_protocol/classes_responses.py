from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .classes import KPXProtocolResponse


class ChangePublicKeysResponse(KPXProtocolResponse):
    """
{
    "action": "change-public-keys",
    "version": "2.7.0",
    "publicKey": "<host public key>",
    "success": "true"
}
    """
    action: str
    version: str
    publicKey: str
    success: Literal["true"]


class GetDatabasehashResponse(KPXProtocolResponse):
    """
{
    "action": "hash",
    "hash": "29234e32274a32276e25666a42",
    "version": "2.2.0"
}
    """
    hash: str
    version: str
    nonce: str
    success: Literal["true"]


class AssociateResponse(KPXProtocolResponse):
    """
{
    "hash": "29234e32274a32276e25666a42",
    "version": "2.7.0",
    "success": "true",
    "id": "testclient",
    "nonce": "tZvLrBzkQ9GxXq9PvKJj4iAnfPT0VZ3Q"
}
    """
    hash: str
    version: str
    success: Literal["true"]
    id: str
    nonce: str


class TestAssociateResponse(KPXProtocolResponse):
    """
{
    "version": "2.7.0",
    "nonce": "tZvLrBzkQ9GxXq9PvKJj4iAnfPT0VZ3Q",
    "hash": "29234e32274a32276e25666a42",
    "id": "testclient",
    "success": "true"
}
    """
    hash: str
    version: str
    success: Literal["true"]
    id: str
    nonce: str


class Login(BaseModel):
    login: str
    name: str
    password: str


class GetLoginsResponse(KPXProtocolResponse):
    """
{
    "count": "2",
    "entries" : [
    {
        "login": "user1",
        "name": "user1",
        "password": "passwd1"
    },
    {
        "login": "user2",
        "name": "user2",
        "password": "passwd2",
        "expired": "true"
    }],
    "nonce": "tZvLrBzkQ9GxXq9PvKJj4iAnfPT0VZ3Q",
    "success": "true",
    "hash": "29234e32274a32276e25666a42",
    "version": "2.2.0"
}
    """
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