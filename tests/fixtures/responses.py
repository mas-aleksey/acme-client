from typing import Dict

import pytest

DIRECTORY = {
    "keyChange": "https://acme-v02.api.letsencrypt.org/acme/key-change",
    "m3T4U0_0EbA": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
    "meta": {
        "caaIdentities": ["letsencrypt.org"],
        "termsOfService": "https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf",
        "website": "https://letsencrypt.org",
    },
    "newAccount": "https://acme-v02.api.letsencrypt.org/acme/new-acct",
    "newNonce": "https://acme-v02.api.letsencrypt.org/acme/new-nonce",
    "newOrder": "https://acme-v02.api.letsencrypt.org/acme/new-order",
    "renewalInfo": "https://acme-v02.api.letsencrypt.org/draft-ietf-acme-ari-01/renewalInfo/",
    "revokeCert": "https://acme-v02.api.letsencrypt.org/acme/revoke-cert",
}

NONCE_HEADERS = {
    "Server": "nginx",
    "Date": "Wed, 20 Sep 2023 10:58:16 GMT",
    "Connection": "keep-alive",
    "Cache-Control": "public, max-age=0, no-cache",
    "Link": '<https://acme-v02.api.letsencrypt.org/directory>;rel="index"',
    "Replay-Nonce": "ZKFe2RaLT0KCLeBe-v3DeifD6kJlYuAKIwd9pkeHoIeCuci06Bw",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=604800",
}

NEW_ACC_HEADERS = {
    "Server": "nginx",
    "Date": "Wed, 20 Sep 2023 10:58:16 GMT",
    "Content-Type": "application/json",
    "Content-Length": "475",
    "Connection": "keep-alive",
    "Boulder-Requester": "1294923266",
    "Cache-Control": "public, max-age=0, no-cache",
    "Link": '<https://acme-v02.api.letsencrypt.org/directory>;rel="index"',
    "Location": "https://acme-v02.api.letsencrypt.org/acme/acct/1327456056",
    "Replay-Nonce": "k01JHcR-ZEi9-0GadotziPubWKQlo2ggPR9Zv3LQJbYSRZygNAo",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=604800",
}

NEW_ACC_RESPONSE = {
    "key": {
        "kty": "RSA",
        "n": "056_ciJ8yb-2-24_S1Qh-8BEtq1TNdtdOeQd_2L4g0qub3YmGBrQav3CJLB-zhkBgcXSs7l4zxIDQ",
        "e": "AQAB",
    },
    "contact": ["mailto:alex@maiul.ru"],
    "initialIp": "79.139.138.21",
    "createdAt": "2023-09-25T07:15:45.96250392Z",
    "status": "valid",
}

NEW_ORDER_HEADERS = {
    "Server": "nginx",
    "Date": "Wed, 20 Sep 2023 10:58:16 GMT",
    "Content-Type": "application/json",
    "Content-Length": "475",
    "Connection": "keep-alive",
    "Boulder-Requester": "1294923266",
    "Cache-Control": "public, max-age=0, no-cache",
    "Link": '<https://acme-v02.api.letsencrypt.org/directory>;rel="index"',
    "Location": "https://acme-v02.api.letsencrypt.org/acme/order/1294923266/209651406546",
    "Replay-Nonce": "k01JHcR-ZEi9-0GadotziPubWKQlo2ggPR9Zv3LQJbYSRZygNAo",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=604800",
}

ORDER_RESPONSE = {
    "status": "pending",
    "expires": "2023-09-27T10:58:16Z",
    "identifiers": [
        {"type": "dns", "value": "example.com"},
        {"type": "dns", "value": "www.example.com"},
    ],
    "authorizations": [
        "https://acme-v02.api.letsencrypt.org/acme/authz-v3/266225761226",
        "https://acme-v02.api.letsencrypt.org/acme/authz-v3/266225761236",
    ],
    "finalize": "https://acme-v02.api.letsencrypt.org/acme/finalize/1294923266/209651406546",
}

CHALLENGES = {
    "identifier": {"type": "dns", "value": "example.com"},
    "status": "pending",
    "expires": "2023-09-27T10:58:16Z",
    "challenges": [
        {
            "type": "http-01",
            "status": "pending",
            "url": "https://acme-v02.api.letsencrypt.org/acme/chall-v3/266225761226/e0rwzA",
            "token": "UowxLeE9ZcQxzLwBWD55Iy6pQwoZLosqIRO0cUKwxDQ",
        },
        {
            "type": "dns-01",
            "status": "pending",
            "url": "https://acme-v02.api.letsencrypt.org/acme/chall-v3/266225761226/C5uTtQ",
            "token": "UowxLeE9ZcQxzLwBWD55Iy6pQwoZLosqIRO0cUKwxDQ",
        },
        {
            "type": "tls-alpn-01",
            "status": "pending",
            "url": "https://acme-v02.api.letsencrypt.org/acme/chall-v3/266225761226/JwbBTg",
            "token": "UowxLeE9ZcQxzLwBWD55Iy6pQwoZLosqIRO0cUKwxDQ",
        },
    ],
}

CHALLENGE_INFO = {
    "type": "dns-01",
    "status": "pending",
    "url": "https://acme-v02.api.letsencrypt.org/acme/chall-v3/266225761226/C5uTtQ",
    "token": "UowxLeE9ZcQxzLwBWD55Iy6pQwoZLosqIRO0cUKwxDQ",
}


@pytest.fixture
def directory_response() -> Dict:
    return DIRECTORY


@pytest.fixture
def nonce_headers() -> Dict:
    return NONCE_HEADERS


@pytest.fixture
def new_acc_headers() -> Dict:
    return NEW_ACC_HEADERS


@pytest.fixture
def acc_kid() -> str:
    return NEW_ACC_HEADERS["Location"]


@pytest.fixture
def new_acc_response() -> Dict:
    return NEW_ACC_RESPONSE


@pytest.fixture
def new_order_headers() -> Dict:
    return NEW_ORDER_HEADERS


@pytest.fixture
def order_response() -> Dict:
    return ORDER_RESPONSE


@pytest.fixture
def challenges() -> Dict:
    return CHALLENGES


@pytest.fixture
def challenge_info() -> Dict:
    return CHALLENGE_INFO
