import pytest

import keepassxc_protocol


@pytest.fixture(scope='module')
def con() -> keepassxc_protocol.Connection:
    con = keepassxc_protocol.Connection()
    con.load_associates_json(
        '{"entries":{"8f1b004cbd837de560b9257b61443f9ae21ee24f4561c87b8f2bb3a6fa7627e0":{"db_hash":"8f1b004cbd837de560b9257b61443f9ae21ee24f4561c87b8f2bb3a6fa7627e0","id":"test","key":"cb7d74ec0efcccbbb23677bc4481fe0325861ce5dd24e4dfb436fe5751fb3429"}}}'
    )
    return con


def test_test_associate(con: keepassxc_protocol.Connection) -> None:
    response = con.test_associate()
    assert response.success == "true"


def test_get_databasehash(con: keepassxc_protocol.Connection) -> None:
    response = con.get_databasehash()


def test_get_logins(con: keepassxc_protocol.Connection) -> None:
    response = con.get_logins(url="sdfalkcxvz.online")
    entry = response.entries[0]
    assert entry.login == "sdafasd"
    assert entry.password == "vczxvxczvzxc"
    assert entry.name == "sadfasdf"


def test_get_database_groups(con: keepassxc_protocol.Connection) -> None:
    response = con.get_database_groups()
