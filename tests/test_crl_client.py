import datetime

import httpx
import pytest
from cryptography.hazmat.primitives import serialization

from dossier.crl_client import CrlClient
from tests import pki_maker
from tests.pki_maker import generate_crl

_NOW = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)

_PARTITION_1_URI = "http://ca.example/part-1.crl"
_PARTITION_2_URI = "http://ca.example/part-2.crl"

_FULL_URI = "http://ca.example/full.crl"

_ROOT = pki_maker.generate_root()
_PARTITIONED_CA = pki_maker.generate_inter_a_key_1_ca(_ROOT)
_FULL_CA = pki_maker.generate_inter_b_ca(_ROOT)


_PARTITIONED_CRLS = {
    _PARTITION_1_URI: generate_crl(
        _PARTITIONED_CA,
        pki_maker.RFC9500_INTER_A_KEY_1,
        [(1, _NOW, None)],
        _PARTITION_1_URI,
    ).public_bytes(serialization.Encoding.DER),
    _PARTITION_2_URI: generate_crl(
        _PARTITIONED_CA, pki_maker.RFC9500_INTER_A_KEY_1, [], _PARTITION_2_URI
    ).public_bytes(serialization.Encoding.DER),
}
_FULL_CRL = generate_crl(
    _FULL_CA, pki_maker.RFC9500_INTER_B_KEY, [(1, _NOW, None)]
).public_bytes(serialization.Encoding.DER)


def _create_null_http_client() -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b""))
    )


def _create_http_client(content: bytes, status_code: int = 200) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(status_code, content=content)
        )
    )


def test_reject_both_full_and_partitioned_crls():
    with pytest.raises(ValueError):
        CrlClient(
            _FULL_CA,
            _create_null_http_client(),
            _NOW,
            crl_full_uri=_FULL_URI,
            crl_partitioned_uris=list(_PARTITIONED_CRLS.keys()),
        )


def test_reject_neither_full_nor_partitioned_crls():
    with pytest.raises(ValueError):
        CrlClient(
            _FULL_CA,
            _create_null_http_client(),
            _NOW,
        )


def test_download_crl_404():
    http_client = _create_http_client(b"Not Found", status_code=404)

    with pytest.raises(httpx.HTTPStatusError):
        CrlClient(
            _FULL_CA,
            http_client,
            _NOW,
            crl_full_uri=_FULL_URI,
        )


def test_download_crl_invalid_content():

    http_client = _create_http_client(b"Invalid CRL content", status_code=200)

    with pytest.raises(ValueError):
        CrlClient(
            _FULL_CA,
            http_client,
            _NOW,
            crl_full_uri=_FULL_URI,
        )


def test_validate_mismatched_issuer():
    http_client = _create_http_client(_FULL_CRL, status_code=200)

    with pytest.raises(ValueError):
        CrlClient(
            _PARTITIONED_CA,
            http_client,
            crl_full_uri=_FULL_URI,
            current_time=_NOW,
        )


def test_validate_expired_crl():
    http_client = _create_http_client(_FULL_CRL, status_code=200)

    with pytest.raises(ValueError):
        CrlClient(
            _FULL_CA,
            http_client,
            crl_full_uri=_FULL_URI,
            current_time=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        )


def test_validate_partitioned_crl_no_idp():
    http_client = _create_http_client(_FULL_CRL, status_code=200)

    with pytest.raises(ValueError):
        CrlClient(
            _FULL_CA,
            http_client,
            crl_partitioned_uris=list(_PARTITIONED_CRLS.keys()),
            current_time=_NOW,
        )


def test_validate_full_crl_with_idp():
    http_client = _create_http_client(
        next(iter(_PARTITIONED_CRLS.values())), status_code=200
    )

    with pytest.raises(ValueError):
        CrlClient(
            _PARTITIONED_CA,
            http_client,
            crl_full_uri=_FULL_URI,
            current_time=_NOW,
        )


def test_cert_not_revoked_full():
    http_client = _create_http_client(_FULL_CRL, status_code=200)

    client = CrlClient(
        _FULL_CA,
        http_client,
        crl_full_uri=_FULL_URI,
        current_time=_NOW,
    )

    assert client.get_revocation_status(14) is None


def test_cert_revoked_full():
    http_client = _create_http_client(_FULL_CRL, status_code=200)

    client = CrlClient(
        _FULL_CA,
        http_client,
        crl_full_uri=_FULL_URI,
        current_time=_NOW,
    )

    assert client.get_revocation_status(1) is not None


def test_cert_not_revoked_partitioned():
    def handle_request(request: httpx.Request) -> httpx.Response:
        content = _PARTITIONED_CRLS[request.url]

        return httpx.Response(200, content=content)

    http_client = httpx.Client(transport=httpx.MockTransport(handle_request))

    client = CrlClient(
        _PARTITIONED_CA,
        http_client,
        crl_partitioned_uris=list(_PARTITIONED_CRLS.keys()),
        current_time=_NOW,
    )

    assert client.get_revocation_status(14) is None


def test_cert_revoked_partitioned():
    def handle_request(request: httpx.Request) -> httpx.Response:
        content = _PARTITIONED_CRLS[request.url]

        return httpx.Response(200, content=content)

    http_client = httpx.Client(transport=httpx.MockTransport(handle_request))

    client = CrlClient(
        _PARTITIONED_CA,
        http_client,
        crl_partitioned_uris=list(_PARTITIONED_CRLS.keys()),
        current_time=_NOW,
    )

    assert client.get_revocation_status(1) is not None
