from typing import Dict

import pytest
from aioresponses import aioresponses

from acme_client import ACMEClient, RSAKey
from acme_client._schemas import Challenge, Challenges, LetsencryptOrder


@pytest.mark.parametrize(
    "key,value",
    [
        ("newAccount", "https://acme-v02.api.letsencrypt.org/acme/new-acct"),
        ("newNonce", "https://acme-v02.api.letsencrypt.org/acme/new-nonce"),
        ("newOrder", "https://acme-v02.api.letsencrypt.org/acme/new-order"),
        ("renewalInfo", "https://acme-v02.api.letsencrypt.org/draft-ietf-acme-ari-01/renewalInfo/"),
        ("revokeCert", "https://acme-v02.api.letsencrypt.org/acme/revoke-cert"),
    ],
)
async def test_get_directory(client: ACMEClient, directory_response: Dict, key: str, value: str):
    with aioresponses() as m:
        m.get(client.base_path, status=200, payload=directory_response)
        resp = await client.get_directory_path(key)
    assert resp == value


async def test_get_new_nonce(client: ACMEClient, directory_response: Dict, nonce_headers: Dict):
    with aioresponses() as m:
        m.get(client.base_path, status=200, payload=directory_response)
        m.get(directory_response["newNonce"], status=200, payload={}, headers=nonce_headers)
        resp = await client.get_new_nonce()
    assert resp == nonce_headers["Replay-Nonce"]


async def test_new_account(
    client: ACMEClient,
    directory_response: Dict,
    nonce_headers: Dict,
    new_acc_response: Dict,
    new_acc_headers: Dict,
    rsa_key: RSAKey,
):
    with aioresponses() as m:
        m.get(client.base_path, status=200, payload=directory_response)
        m.get(directory_response["newNonce"], status=200, payload={}, headers=nonce_headers)
        m.post(
            directory_response["newAccount"],
            status=201,
            payload=new_acc_response,
            headers=new_acc_headers,
        )
        acc_url = await client.new_account(rsa_key)
    assert acc_url == new_acc_headers["Location"]


async def test_new_order(
    client: ACMEClient,
    directory_response: Dict,
    nonce_headers: Dict,
    acc_kid: str,
    order_response: Dict,
    new_order_headers: Dict,
    rsa_key: RSAKey,
):
    with aioresponses() as m:
        m.get(client.base_path, status=200, payload=directory_response)
        m.get(directory_response["newNonce"], status=200, payload={}, headers=nonce_headers)
        m.post(
            directory_response["newOrder"],
            status=201,
            payload=order_response,
            headers=new_order_headers,
        )
        order, order_url = await client.new_order(rsa_key, ["example.com"], acc_kid)
    assert order == LetsencryptOrder.parse_obj(order_response)
    assert order_url == new_order_headers["Location"]


async def test_get_auth_info(
    client: ACMEClient,
    directory_response: Dict,
    nonce_headers: Dict,
    order_response: Dict,
    challenges: Dict,
    acc_kid: str,
    rsa_key: RSAKey,
):
    with aioresponses() as m:
        m.get(client.base_path, status=200, payload=directory_response)
        m.get(directory_response["newNonce"], status=200, payload={}, headers=nonce_headers)
        m.post(order_response["authorizations"][0], status=200, payload=challenges)
        auth_info = await client.get_auth_info(
            rsa_key, order_response["authorizations"][0], acc_kid
        )
    assert auth_info == Challenges.parse_obj(challenges)


async def test_get_order_info(
    client: ACMEClient,
    directory_response: Dict,
    nonce_headers: Dict,
    new_order_headers: Dict,
    order_response: Dict,
    acc_kid: str,
    rsa_key: RSAKey,
):
    order_url = new_order_headers["Location"]
    with aioresponses() as m:
        m.get(client.base_path, status=200, payload=directory_response)
        m.get(directory_response["newNonce"], status=200, payload={}, headers=nonce_headers)
        m.post(order_url, status=200, payload=order_response)
        order = await client.get_order_info(rsa_key, order_url, acc_kid)
    assert order == LetsencryptOrder.parse_obj(order_response)


async def test_say_challenge_is_done(
    client: ACMEClient,
    directory_response: Dict,
    nonce_headers: Dict,
    challenge_info: Dict,
    challenges: Dict,
    acc_kid: str,
    rsa_key: RSAKey,
):
    challenge_url = challenges["challenges"][0]["url"]
    with aioresponses() as m:
        m.get(client.base_path, status=200, payload=directory_response)
        m.get(directory_response["newNonce"], status=200, payload={}, headers=nonce_headers)
        m.post(challenge_url, status=200, payload=challenge_info)
        challenge = await client.say_challenge_is_done(rsa_key, challenge_url, acc_kid)
    assert challenge == Challenge.parse_obj(challenge_info)


async def test_finalize_order(
    client: ACMEClient,
    directory_response: Dict,
    nonce_headers: Dict,
    new_order_headers: Dict,
    order_response: Dict,
    acc_kid: str,
    rsa_key: RSAKey,
):
    order_url = new_order_headers["Location"]
    with aioresponses() as m:
        m.get(client.base_path, status=200, payload=directory_response)
        m.get(directory_response["newNonce"], status=200, payload={}, headers=nonce_headers)
        m.post(order_url, status=200, payload=order_response)
        await client.finalize_order(rsa_key, order_url, rsa_key.make_csr("example.com"), acc_kid)


async def test_download_chain(
    client: ACMEClient,
    directory_response: Dict,
    nonce_headers: Dict,
    new_order_headers: Dict,
    acc_kid: str,
    rsa_key: RSAKey,
    self_signed_pem: bytes,
):
    order_url = new_order_headers["Location"]
    with aioresponses() as m:
        m.get(client.base_path, status=200, payload=directory_response)
        m.get(directory_response["newNonce"], status=200, payload={}, headers=nonce_headers)
        m.post(order_url, status=200, body=self_signed_pem)
        chain = await client.download_chain(rsa_key, order_url, acc_kid)
    assert chain == self_signed_pem.decode("utf-8")


async def test_revoke(
    client: ACMEClient,
    directory_response: Dict,
    nonce_headers: Dict,
    rsa_key: RSAKey,
    acc_kid: str,
    self_signed_der: bytes,
):
    with aioresponses() as m:
        m.get(client.base_path, status=200, payload=directory_response)
        m.get(directory_response["newNonce"], status=200, payload={}, headers=nonce_headers)
        m.post(directory_response["revokeCert"], status=204)
        await client.revoke(rsa_key, self_signed_der, acc_kid)
