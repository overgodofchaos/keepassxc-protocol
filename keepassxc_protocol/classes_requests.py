import base64

from nacl.public import Box, PrivateKey, PublicKey
from pydantic import Field, PrivateAttr, computed_field

from . import classes_responses as responses
from .classes import KPXProtocolRequest, KPXProtocolResponse
from .connection_config import Associates


# noinspection PyPep8Naming
class ChangePublicKeysRequest(KPXProtocolRequest[responses.ChangePublicKeysResponse]):
    """
{
    "action": "change-public-keys",
    "publicKey": "<client public key>",
    "nonce": "tZvLrBzkQ9GxXq9PvKJj4iAnfPT0VZ3Q",
    "clientID": "<clientID>"
}
    """
    _action: str = PrivateAttr("change-public-keys")
    _response = responses.ChangePublicKeysResponse

    @computed_field()
    def publicKey(self) -> str:
        return self.config.public_key_utf8

    @computed_field()
    def nonce(self) -> str:
        return self.config.nonce_utf8

    @computed_field()
    def clientID(self) -> str:
        return self.config.client_id


class GetDatabasehashRequest(KPXProtocolRequest[responses.GetDatabasehashResponse]):
    """
{
    "action": "get-databasehash"
}
    """
    _action: str = PrivateAttr("get-databasehash")
    _response = responses.GetDatabasehashResponse


class AssociateRequest(KPXProtocolRequest[responses.AssociateResponse]):
    """
{
    "action": "associate",
    "key": "<client public key>",
    "idKey": "<a new identification public key>"
}
    """
    _action: str = PrivateAttr("associate")
    _response = responses.AssociateResponse
    id_public_key: PublicKey = Field(exclude=True)

    @computed_field()
    def key(self) -> str:
        return self.config.public_key_utf8

    # noinspection PyPep8Naming
    @computed_field()
    def idKey(self) -> str:
        # noinspection PyProtectedMember
        return base64.b64encode(self.id_public_key._public_key).decode("utf-8")


class TestAssociateRequest(KPXProtocolRequest[responses.TestAssociateResponse]):
    """
{
    "action": "test-associate",
    "id": "<saved database identifier received from associate>",
    "key": "<saved identification public key>"
}
    """
    _action: str = PrivateAttr("test-associate")
    _response = responses.TestAssociateResponse
    id: str
    key: str


class GetLoginsRequest(KPXProtocolRequest[responses.GetLoginsResponse]):
    """
{
    "action": "get-logins",
    "url": "<snip>",
    "submitUrl": "<optional>",
    "httpAuth": "<optional>",
    "keys": [
        {
            "id": "<saved database identifier received from associate>",
            "key": "<saved identification public key>"
        },
        ...
    ]
}
    """
    _action: str = PrivateAttr("get-logins")
    _response = responses.GetLoginsResponse
    url: str
    associates: Associates = Field(exclude=True)
    db_hash: str = Field(exclude=True)

    @computed_field()
    def keys(self) -> list[dict[str, str]]:
        cada = self.associates.get_by_hash(self.db_hash)  # current active db associate

        others = [a for a in self.associates.list if a.db_hash != cada.db_hash]

        return [{"id": a.id, "key": a.key_utf8} for a in [cada, *others]]


class GetDatabaseGroupsRequest(KPXProtocolRequest[responses.GetDatabaseGroupsResponse]):
    """
{
    "action": "get-database-groups"
}
    """
    _action: str = PrivateAttr("get-database-groups")
    _response = responses.GetDatabaseGroupsResponse


