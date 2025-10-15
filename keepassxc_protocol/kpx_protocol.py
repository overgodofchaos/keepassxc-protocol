# Refer to https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md
import base64
import json
import os
import platform
import socket
from collections.abc import Buffer
from typing import Any, TypeVar

import nacl.utils
from loguru import logger
from nacl.public import Box, PrivateKey, PublicKey
from pydantic import ValidationError

from . import classes_requests as req
from . import classes_responses as resp
from .connection_session import Associate, Associates, ConnectionSession
from .errors import ResponseUnsuccesfulException
from .winpipe import WinNamedPipe

log = logger

if platform.system() == "Windows":
    import win32file

_R = TypeVar("_R", bound=resp.BaseResponse)


class Connection:
    def __init__(self) -> None:

        if platform.system() == "Windows":
            socket_ = WinNamedPipe(win32file.GENERIC_READ | win32file.GENERIC_WRITE, win32file.OPEN_EXISTING)
        else:
            socket_ = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        self.session = ConnectionSession(
            private_key=PrivateKey.generate(),
            nonce=nacl.utils.random(24),
            client_id=base64.b64encode(nacl.utils.random(24)).decode("utf-8"),
            box=None,
            socket=socket_
        )

        response = self.change_public_keys()
        self.session.box = Box(self.session.private_key, PublicKey(base64.b64decode(response.publicKey)))
        log.debug(f"Session: {self.session}")


    def _request(self, message: req.BaseRequest | req.BaseMessage, response_type: type[_R]) -> _R:

        def get_response() -> dict:
            def decrypt(raw_data: dict) -> dict:
                server_nonce = base64.b64decode(raw_data["nonce"])
                decrypted = self.session.box.decrypt(base64.b64decode(raw_data["message"]), server_nonce)
                unencrypted_message = json.loads(decrypted)

                return unencrypted_message

            json_data = json.loads(
                self.session.receive()
            )

            if "error" in json_data:
                raise ResponseUnsuccesfulException(json_data)

            if "message" in json_data:
                response = decrypt(json_data)
            else:
                response = json_data

            return response

        def encrypt_message(unencrypted_message: req.BaseMessage) -> req.EncryptedRequest:
            log.debug(f"Unencrypted message:\n{unencrypted_message.model_dump_json(indent=2)}\n")
            return req.EncryptedRequest(session=self.session, unencrypted_message=unencrypted_message)

        def send(request: req.BaseRequest) -> dict:
            log.debug(f"Sending request:\n{request.model_dump_json(indent=2)}\n")

            request = request.to_bytes()
            self.session.sendall(request)
            self.session.increase_nonce()

            response = get_response()

            log.debug(f"Response:\n{json.dumps(response, indent=2)}")

            return response

        if isinstance(message, req.BaseRequest):
            data = send(message)
        else:
            encrypted_message = encrypt_message(message)
            data = send(encrypted_message)

        try:
            return response_type.model_validate(data)
        except ValidationError as e:
            data_ = json.dumps(data, indent=2)
            raise ResponseUnsuccesfulException(f"{data_}\n{e!s}") from Exception

    def change_public_keys(self) -> resp.ChangePublicKeysResponse:
        message = req.ChangePublicKeysRequest(session=self.session)
        return self._request(message, resp.ChangePublicKeysResponse)

    def get_databasehash(self) -> resp.GetDatabasehashResponse:
        message = req.GetDatabasehashMessage(session=self.session)
        return self._request(message, resp.GetDatabasehashResponse)

    def associate(self) -> resp.AssociateResponse:
        id_public_key = PrivateKey.generate().public_key

        message = req.AssociateMessage(session=self.session, id_public_key=id_public_key)
        response = self._request(message, resp.AssociateResponse)

        db_hash = self.get_databasehash().hash

        self.session.associates.add(
            db_hash=db_hash, associate=Associate(db_hash=db_hash, id=response.id, key=id_public_key))

        self.test_associate()
        return response

    def load_associates_json(self, associates_json: str) -> None:
        """Loads associates from JSON string"""
        self.session.associates = Associates.model_validate_json(associates_json)
        self.test_associate()

    def load_associates(self, associates: Associates) -> None:
        """Loads associates from Associates object"""
        self.session.associates = associates.model_copy(deep=True)
        self.test_associate()

    def dump_associate_json(self) -> str:
        """Dumps associates to JSON string"""
        return self.session.associates.model_dump_json()

    def dump_associates(self) -> Associates:
        """Domps associates to Associates object"""
        return self.session.associates.model_copy(deep=True)

    def test_associate(self, trigger_unlock: bool = False) -> resp.TestAssociateResponse:
        db_hash = self.get_databasehash().hash
        associate = self.session.associates.get_by_hash(db_hash)

        log.debug(f"DB hash: {db_hash}")
        log.debug(f"Associate: {associate}")

        message = req.TestAssociateMessage(
            session=self.session,
            id=associate.id,
            key=associate.key_utf8,
        )
        return self._request(message, resp.TestAssociateResponse)


    def get_logins(self, url: str) -> resp.GetLoginsResponse:
        # noinspection HttpUrlsUsage
        if url.startswith("https://") is False \
                and url.startswith("http://") is False:
            url = f"https://{url}"

        db_hash = self.get_databasehash().hash

        message = req.GetLoginsMessage(
            session=self.session,
            url=url,
            associates=self.session.associates,
            db_hash=db_hash,
        )

        return self._request(message, resp.GetLoginsResponse)

    def get_database_groups(self) -> resp.GetDatabaseGroupsResponse:
        message = req.GetDatabaseGroupsMessage(session=self.session)
        return self._request(message, resp.GetDatabaseGroupsResponse)
