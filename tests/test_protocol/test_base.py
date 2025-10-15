import pytest

import keepassxc_protocol


@pytest.fixture(scope='module')
def con() -> keepassxc_protocol.Connection:
    with open("./tests/files/associate_data.json", encoding="utf-8") as f:
        associate_data = f.read()

    con = keepassxc_protocol.Connection()
    con.load_associates_json(associate_data)
    return con


def test_test_associate(con: keepassxc_protocol.Connection) -> None:
    response = con.test_associate()
    assert response.success == "true"


def test_get_databasehash(con: keepassxc_protocol.Connection) -> None:
    response = con.get_databasehash()
    assert response.hash == "8f1b004cbd837de560b9257b61443f9ae21ee24f4561c87b8f2bb3a6fa7627e0"


def test_get_logins(con: keepassxc_protocol.Connection) -> None:
    response = con.get_logins(url="sdfalkcxvz.online")
    entry = response.entries[0]
    assert entry.login == "sdafasd"
    assert entry.password == "vczxvxczvzxc"
    assert entry.name == "sadfasdf"


def test_get_database_groups(con: keepassxc_protocol.Connection) -> None:
    response = con.get_database_groups()
    groups = response.groups.groups

    group_main = next((g for g in groups if g.name == "main"), None)
    assert group_main is not None
    group0 = next((g for g in group_main.children if g.name == "group0"), None)
    assert group0 is not None
    group01 = next((g for g in group0.children if g.name == "group01"), None)
    assert group01 is not None
    group010 = next((g for g in group01.children if g.name == "group010"), None)
    assert group010 is not None
    assert group010.uuid == "e6f5966e767940e8b5cf6ffed315e3b6"
