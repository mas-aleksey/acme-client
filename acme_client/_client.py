"""
ACME client for Python.

This is a Python implementation of the ACME protocol.
It is designed to be used with the `async_client` library.
"""

import base64
import json
from typing import Dict, Optional, Union

from async_client import BaseClient, ClientConfig

from acme_client._rsa_utils import RSAKey
from acme_client._schemas import Challenge, Challenges, LetsencryptOrder


class ACMESettings(ClientConfig):
    EMAIL: str


class ACMEClient(BaseClient):
    def __init__(self, config: ACMESettings) -> None:
        super().__init__(config)
        self._directory = None

    @property
    def headers(self) -> dict:
        return {
            "Content-Type": "application/jose+json",
        }

    @staticmethod
    def _safe_base64(un_encoded_data: Union[str, bytes]) -> str:
        """
        ACME-safe base64 encoding of un_encoded_data as a string
        Args:
            un_encoded_data: The data to encode.
        Returns:
            The encoded data as a string.
        """
        if isinstance(un_encoded_data, str):
            un_encoded_data = un_encoded_data.encode("utf8")
        r = base64.urlsafe_b64encode(un_encoded_data).rstrip(b"=")
        return r.decode("utf8")

    async def get_directory_path(self, key: str) -> str:
        """
        Get the path for a directory key.
        Possible keys: 'newNonce', 'newAccount', 'newOrder' 'revokeCert' 'keyChange'
        Args:
            key: The key to get the path for.
        Returns:
            The path for the key.
        """
        if not self._directory:
            resp = await self._perform_request("get", self.base_path)
            self._directory = json.loads(resp.body.decode("utf8"))
        return self._directory[key]

    async def _make_signed_json(
        self, url: str, key: RSAKey, payload: Optional[Dict], kid: Optional[str]
    ) -> Dict[str, str]:
        """
        Make a signed JSON object.
        Args:
            url: The URL to sign.
            key: The RSAKey object to use for the signature.
            payload: The payload to sign.
            kid: The kid to use for the signature.
        Returns:
            The signed JSON object.
        """
        payload_bytes = json.dumps(payload).encode() if payload is not None else b""
        payload64 = self._safe_base64(payload_bytes)
        nonce = await self.get_new_nonce()
        protected = {"alg": key.alg, "kid": kid, "nonce": nonce, "url": url}
        protected.update({"kid": kid} if kid else {"jwk": key.jwk_json})

        protected64 = self._safe_base64(json.dumps(protected))
        message = ("%s.%s" % (protected64, payload64)).encode("utf-8")
        signature64 = self._safe_base64(key.sign(message))
        return {
            "protected": protected64,
            "payload": payload64,
            "signature": signature64,
        }

    async def get_new_nonce(self, path: str = "newNonce") -> str:
        """
        Get a new nonce from the ACME server.
        This is used to prevent replay attacks.
        Args:
            path: The path to the nonce endpoint.
        Returns:
            The nonce as a string.
        """
        url = await self.get_directory_path(path)
        resp = await self._perform_request("get", url)
        return resp.headers["Replay-Nonce"]

    async def new_account(self, key: RSAKey, path: str = "newAccount") -> str:
        """
        Create a new account on the ACME server.
        Args:
            key: The RSAKey object to use for the account.
            path: The path to the account endpoint.
        Returns:
            The URL of the new account.
        """
        payload = {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:{self.config.EMAIL}"],
        }
        url = await self.get_directory_path(path)
        signed_json = await self._make_signed_json(url, key, payload, None)
        resp = await self._perform_request("post", url, json=signed_json, headers=self.headers)
        return resp.headers.get("Location")

    async def new_order(
        self, key: RSAKey, domains: list[str], kid: str, path: str = "newOrder"
    ) -> tuple[LetsencryptOrder, str]:
        """
        Create a new order on the ACME server.
        Args:
            key: The RSAKey object to use for the order.
            domains: The list of domains to order certificates for.
            kid: The kid to use for the order.
            path: The path to the order endpoint.
        Returns:
            A tuple containing the LetsencryptOrder object and the URL of the new order.
        """
        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        url = await self.get_directory_path(path)
        signed_json = await self._make_signed_json(url, key, payload, kid)
        resp = await self._perform_request("post", url, json=signed_json, headers=self.headers)
        return self.load_schema(resp.body, LetsencryptOrder), resp.headers.get("Location")

    async def get_auth_info(self, key: RSAKey, auth_url: str, kid: str) -> Challenges:
        """
        Get the authorization information for the order.
        Args:
            key: The RSAKey object to use for the authorization.
            auth_url: The URL of the authorization.
            kid: The kid to use for the authorization.
        Returns:
            The Challenges object.
        """
        signed_json = await self._make_signed_json(auth_url, key, None, kid)
        resp = await self._perform_request("post", auth_url, json=signed_json, headers=self.headers)
        return self.load_schema(resp.body, Challenges)

    async def get_order_info(self, key: RSAKey, order_url: str, kid: str) -> LetsencryptOrder:
        """
        Get the order information for the order.
        Args:
            key: The RSAKey object to use for the order.
            order_url: The URL of the order.
            kid: The kid to use for the order.
        Returns:
            The LetsencryptOrder object.
        """
        signed_json = await self._make_signed_json(order_url, key, None, kid)
        resp = await self._perform_request(
            "post", order_url, json=signed_json, headers=self.headers
        )
        return self.load_schema(resp.body, LetsencryptOrder)

    async def say_challenge_is_done(self, key: RSAKey, url: str, kid: str) -> Challenge:
        """
        Say that the challenge is done.
        Args:
            key: The RSAKey object to use for the challenge.
            url: The URL of the challenge.
            kid: The kid to use for the challenge.
        Returns:
            The Challenge object.
        """
        signed_body = await self._make_signed_json(url, key, {}, kid)
        resp = await self._perform_request("post", url, json=signed_body, headers=self.headers)
        return self.load_schema(resp.body, Challenge)

    async def finalize_order(self, key: RSAKey, url: str, csr: bytes, kid: str) -> None:
        """
        Finalize the order.
        Args:
            key: The RSAKey object to use for the order.
            url: The URL of the order.
            csr: The CSR to use for the order.
            kid: The account kid to use for the order.
        """
        payload = {"csr": self._safe_base64(csr)}
        signed_json = await self._make_signed_json(url, key, payload, kid)
        await self._perform_request("post", url, json=signed_json, headers=self.headers)

    async def download_chain(self, key: RSAKey, url: str, kid: str) -> str:
        """
        Download the chain for the order.
        Args:
            key: The RSAKey object to use for the order.
            url: The URL of the order.
            kid: The kid to use for the order.
        Returns:
            The chain as a string.
        """
        signed_json = await self._make_signed_json(url, key, None, kid)
        resp = await self._perform_request("post", url, json=signed_json, headers=self.headers)
        return resp.body.decode("utf8")

    async def revoke(
        self, key: RSAKey, der_cert_bytes: bytes, kid: str, path: str = "revokeCert"
    ) -> None:
        """
        Revoke a certificate.
        Args:
            key: The RSAKey object to use for the certificate.
            der_cert_bytes: The DER-encoded certificate to revoke.
            kid: The kid to use for the certificate.
            path: The path to the revoke endpoint.
        """
        payload = {"certificate": self._safe_base64(der_cert_bytes), "reason": 0}
        url = await self.get_directory_path(path)
        signed_json = await self._make_signed_json(url, key, payload, kid)
        await self._perform_request("post", url, json=signed_json, headers=self.headers)
