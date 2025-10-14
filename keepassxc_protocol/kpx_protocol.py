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

from . import classes as k
from . import classes_requests as req
from . import classes_responses as resp
from .connection_config import Associate, Associates, ConnectionConfig
from .errors import ResponseUnsuccesfulException
from .winpipe import WinNamedPipe

log = logger

if platform.system() == "Windows":
    import getpass

    import win32file

R = TypeVar("R", bound=resp.BaseResponse)


class Connection:
    def __init__(self) -> None:

        if platform.system() == "Windows":
            self.socket = WinNamedPipe(win32file.GENERIC_READ | win32file.GENERIC_WRITE, win32file.OPEN_EXISTING)
        else:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        self.config = ConnectionConfig(
            private_key=PrivateKey.generate(),
            nonce=nacl.utils.random(24),
            client_id=base64.b64encode(nacl.utils.random(24)).decode("utf-8"),
            box=None
        )

        self._connect()

    def _send(self,
              request: req.BaseRequest
              ) -> dict:

        log.debug(f"Sending request:\n{request.model_dump_json(indent=2)}\n")

        request = request.to_bytes()
        self.socket.sendall(request)
        self.config.increase_nonce()

        response = self._get_response()

        log.debug(f"Response:\n{json.dumps(response, indent=2)}")

        return response


    def _encrypt_message(self,
                         message: req.BaseMessage,
                        ) -> req.EncryptedRequest:

        log.debug(f"Unencrypted message:\n{message.model_dump_json(indent=2)}\n")

        return req.EncryptedRequest(config=self.config, unencrypted_message=message)

    def _decrypt(self, data: dict) -> dict:

        server_nonce = base64.b64decode(data["nonce"])
        decrypted = self.config.box.decrypt(base64.b64decode(data["message"]), server_nonce)
        unencrypted_message = json.loads(decrypted)

        return unencrypted_message

    def _get_response(self) -> dict:
        data = []
        while True:
            new_data = self.socket.recv(4096)
            if new_data:
                data.append(new_data.decode('utf-8'))
            else:
                break
            if len(new_data) < 4096:
                break

        json_data = json.loads("".join(data))

        if "error" in json_data:
            raise ResponseUnsuccesfulException(json_data)

        if "message" in json_data:
            response = self._decrypt(json_data)
        else:
            response = json_data

        return response

    def _connect(self, path: tuple[Any, ...] | str | Buffer | None = None) -> None:
        if path is None:
            path = Connection._get_socket_path()

        self.socket.connect(path)

        response = self.change_public_keys()

        self.config.box = Box(self.config.private_key, PublicKey(base64.b64decode(response.publicKey)))

    @staticmethod
    def _get_socket_path() -> str:
        server_name = "org.keepassxc.KeePassXC.BrowserServer"
        system = platform.system()
        if system == "Linux" and "XDG_RUNTIME_DIR" in os.environ:
            flatpak_socket_path = os.path.join(os.environ["XDG_RUNTIME_DIR"], "app/org.keepassxc.KeePassXC",
                                               server_name)
            if os.path.exists(flatpak_socket_path):
                return flatpak_socket_path
            return os.path.join(os.environ["XDG_RUNTIME_DIR"], server_name)
        elif system == "Darwin" and "TMPDIR" in os.environ:
            return os.path.join(os.getenv("TMPDIR"), server_name)
        elif system == "Windows":
            path_win = "org.keepassxc.KeePassXC.BrowserServer_" + getpass.getuser()
            return path_win
        else:
            return os.path.join("/tmp", server_name)

    def request(self,
                message: req.BaseRequest | req.BaseMessage,
                response_type: type[R]) -> R:
        if isinstance(message, req.BaseRequest):
            data = self._send(message)
        else:
            request = self._encrypt_message(message)
            data = self._send(request)

        try:
            return response_type.model_validate(data)
        except ValidationError as e:
            data_ = json.dumps(data, indent=2)
            raise ResponseUnsuccesfulException(f"{data_}\n{e!s}") from Exception

    def change_public_keys(self) -> resp.ChangePublicKeysResponse:
        message = req.ChangePublicKeysRequest(config=self.config)
        return self.request(message, resp.ChangePublicKeysResponse)

    def get_databasehash(self) -> resp.GetDatabasehashResponse:
        message = req.GetDatabasehashRequest(config=self.config)
        response = message.send(self.send_encrypted)
        return response

    def associate(self) -> resp.AssociateResponse:
        id_public_key = PrivateKey.generate().public_key

        message = req.AssociateRequest(config=self.config, id_public_key=id_public_key)
        response = message.send(self.send_encrypted)
        db_hash = self.get_databasehash().hash

        self.config.associates.add(
            db_hash=db_hash, associate=Associate(db_hash=db_hash, id=response.id, key=id_public_key))

        self.test_associate()
        return response

    def load_associates_json(self, associates_json: str) -> None:
        """Loads associates from JSON string"""
        self.config.associates = Associates.model_validate_json(associates_json)
        self.test_associate()

    def load_associates(self, associates: Associates) -> None:
        """Loads associates from Associates object"""
        self.config.associates = associates.model_copy(deep=True)
        self.test_associate()

    def dump_associate_json(self) -> str:
        """Dumps associates to JSON string"""
        return self.config.associates.model_dump_json()



    def dump_associates(self) -> Associates:
        """Domps associates to Associates object"""
        return self.config.associates.model_copy(deep=True)

    def test_associate(self, trigger_unlock: bool = False) -> resp.TestAssociateResponse:
        db_hash = self.get_databasehash().hash
        associate = self.config.associates.get_by_hash(db_hash)
        message = req.TestAssociateRequest(
            config=self.config,
            id=associate.id,
            key=associate.key_utf8,
        )
        response = message.send(self.send_encrypted)
        return response


    def get_logins(self, url: str) -> resp.GetLoginsResponse:
        # noinspection HttpUrlsUsage
        if url.startswith("https://") is False \
                and url.startswith("http://") is False:
            url = f"https://{url}"

        db_hash = self.get_databasehash().hash

        message = req.GetLoginsRequest(
            config=self.config,
            url=url,
            associates=self.config.associates,
            db_hash=db_hash,
        )

        response = message.send(self.send_encrypted)

        return response

    def get_database_groups(self) -> resp.GetDatabaseGroupsResponse:

        message = req.GetDatabaseGroupsRequest(config=self.config)
        response = message.send(self.send_encrypted)

        return response



