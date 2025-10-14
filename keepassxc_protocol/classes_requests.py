import base64

from nacl.public import PublicKey
from pydantic import Field, PrivateAttr, computed_field

from . import classes_responses as responses
from .classes import KPXProtocol
from .connection_config import Associates, ConnectionConfig


class _BaseMessage(KPXProtocol):
    _action: str = PrivateAttr("none")
    config: ConnectionConfig = Field(exclude=True)

    @computed_field
    @property
    def action(self) -> str:
        return self._action


class BaseMessage(_BaseMessage):
    pass


class BaseRequest(_BaseMessage):
    _action: str = PrivateAttr("none")
    trigger_unlock: bool = Field(default=False, exclude=True)

    @property
    def config(self) -> ConnectionConfig:
        return self.unencrypted_request.config

    @computed_field()
    def nonce(self) -> str:
        return self.config.nonce_utf8

    # noinspection PyPep8Naming
    @computed_field()
    def clientID(self) -> str:
        return self.config.client_id

    # noinspection PyPep8Naming
    @computed_field()
    def triggerUnlock(self) -> str:
        if self.trigger_unlock:
            return "true"
        else:
            return "false"

    def to_bytes(self) -> bytes:
        return self.model_dump_json().encode("utf-8")


class EncryptedRequest(BaseRequest):
    unencrypted_message: BaseMessage = Field(exclude=True)

    @computed_field()
    def action(self) -> str:
        return self.unencrypted_message.action

    @computed_field()
    def message(self) -> str:
        msg = self.unencrypted_message
        encrypted = base64.b64encode(
            self.config.box.encrypt(msg.model_dump_json().encode("utf-8"),
                                    nonce=self.config.nonce).ciphertext)
        return encrypted.decode("utf-8")


# noinspection PyPep8Naming
class ChangePublicKeysRequest(BaseRequest):
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


class GetDatabasehashMessage(BaseMessage):
    """
{
    "action": "get-databasehash"
}
    """
    _action: str = PrivateAttr("get-databasehash")
    _response = responses.GetDatabasehashResponse


class AssociateMessage(BaseMessage):
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


class TestAssociateMessage(BaseMessage):
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


class GetLoginsMessage(BaseMessage):
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


class GetDatabaseGroupsMessage(BaseMessage):
    """
{
    "action": "get-database-groups"
}
    """
    _action: str = PrivateAttr("get-database-groups")
    _response = responses.GetDatabaseGroupsResponse
