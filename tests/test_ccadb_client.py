import datetime

from cryptography.hazmat.primitives import serialization, hashes

from dossier import ccadb_client
from tests import pki_maker
from tests.ccadb_utils import (
    create_http_client,
    write_ccadb_all_certs,
    write_ccadb_pems,
)

_CURRENT_TIME = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)

_ROOT = pki_maker.generate_root()
_ICA_A_KEY_1 = pki_maker.generate_inter_a_key_1_ca(_ROOT)
_ICA_A_KEY_1_PEM = _ICA_A_KEY_1.public_bytes(serialization.Encoding.PEM).decode()
_ICA_A_KEY_2 = pki_maker.generate_inter_a_key_2_ca(_ROOT)
_ICA_A_KEY_2_PEM = _ICA_A_KEY_2.public_bytes(serialization.Encoding.PEM).decode()
_ICA_B = pki_maker.generate_inter_b_ca(_ROOT)
_ICA_B_PEM = _ICA_B.public_bytes(serialization.Encoding.PEM).decode()


def test_ccadb_expired_ica_skipped():
    ica = pki_maker.generate_inter_a_key_1_ca(pki_maker.generate_root())

    pems_bytes = write_ccadb_pems([_ICA_A_KEY_1_PEM])

    entries_bytes = write_ccadb_all_certs(
        [
            {
                "SHA-256 Fingerprint": (
                    _ICA_A_KEY_1.fingerprint(hashes.SHA256()).hex()
                ).upper(),
                "Revocation Status": "Good",
                "Valid To (GMT)": "2023.12.31",
                "Full CRL Issued By This CA": "",
                "JSON Array of Partitioned CRLs": "",
            }
        ]
    )

    client = ccadb_client.CcadbClient(
        create_http_client(pems_bytes, entries_bytes), _CURRENT_TIME, True
    )

    assert not client._issuers_by_name


def test_ccadb_revoked_ica_skipped():
    pems_bytes = write_ccadb_pems([_ICA_A_KEY_1_PEM])

    entries_bytes = write_ccadb_all_certs(
        [
            {
                "SHA-256 Fingerprint": (
                    _ICA_A_KEY_1.fingerprint(hashes.SHA256()).hex()
                ).upper(),
                "Revocation Status": "Revoked",
                "Valid To (GMT)": "2025.12.31",
                "Full CRL Issued By This CA": "",
                "JSON Array of Partitioned CRLs": "",
            }
        ]
    )

    client = ccadb_client.CcadbClient(
        create_http_client(pems_bytes, entries_bytes), _CURRENT_TIME, True
    )

    assert not client._issuers_by_name


def test_ccadb_parent_revoked_ica_skipped():
    pems_bytes = write_ccadb_pems([_ICA_A_KEY_1_PEM])

    entries_bytes = write_ccadb_all_certs(
        [
            {
                "SHA-256 Fingerprint": (
                    _ICA_A_KEY_1.fingerprint(hashes.SHA256()).hex()
                ).upper(),
                "Revocation Status": "Parent Cert Revoked",
                "Valid To (GMT)": "2025.12.31",
                "Full CRL Issued By This CA": "",
                "JSON Array of Partitioned CRLs": "",
            },
        ]
    )

    client = ccadb_client.CcadbClient(
        create_http_client(pems_bytes, entries_bytes), _CURRENT_TIME, True
    )

    assert not client._issuers_by_name


def test_ccadb_parent_valid_ica():
    pems_bytes = write_ccadb_pems([_ICA_A_KEY_1_PEM])

    entries_bytes = write_ccadb_all_certs(
        [
            {
                "SHA-256 Fingerprint": (
                    _ICA_A_KEY_1.fingerprint(hashes.SHA256()).hex()
                ).upper(),
                "Revocation Status": "Good",
                "Valid To (GMT)": "2025.12.31",
                "Full CRL Issued By This CA": "",
                "JSON Array of Partitioned CRLs": "",
            },
        ]
    )

    client = ccadb_client.CcadbClient(
        create_http_client(pems_bytes, entries_bytes), _CURRENT_TIME, True
    )

    assert len(client._issuers_by_name) == 1
    assert client._issuers_by_name[_ICA_A_KEY_1.subject.public_bytes()]


def test_issuer_not_found():
    pems_bytes = write_ccadb_pems([_ICA_A_KEY_1_PEM])

    entries_bytes = write_ccadb_all_certs(
        [
            {
                "SHA-256 Fingerprint": (
                    _ICA_A_KEY_1.fingerprint(hashes.SHA256()).hex()
                ).upper(),
                "Revocation Status": "Good",
                "Valid To (GMT)": "2025.12.31",
                "Full CRL Issued By This CA": "",
                "JSON Array of Partitioned CRLs": "",
            },
        ]
    )

    ee_cert = pki_maker.generate_tls_ee(_ICA_B, pki_maker.RFC9500_INTER_B_KEY)

    client = ccadb_client.CcadbClient(
        create_http_client(pems_bytes, entries_bytes), _CURRENT_TIME, True
    )

    assert client.find_issuer_entry(ee_cert) is None


def test_issuer_found():
    pems_bytes = write_ccadb_pems([_ICA_A_KEY_1_PEM, _ICA_B_PEM])

    entries_bytes = write_ccadb_all_certs(
        [
            {
                "SHA-256 Fingerprint": (
                    _ICA_A_KEY_1.fingerprint(hashes.SHA256()).hex()
                ).upper(),
                "Revocation Status": "Good",
                "Valid To (GMT)": "2025.12.31",
                "Full CRL Issued By This CA": "",
                "JSON Array of Partitioned CRLs": "",
            },
            {
                "SHA-256 Fingerprint": (
                    _ICA_B.fingerprint(hashes.SHA256()).hex()
                ).upper(),
                "Revocation Status": "Good",
                "Valid To (GMT)": "2025.12.31",
                "Full CRL Issued By This CA": "",
                "JSON Array of Partitioned CRLs": "",
            },
        ]
    )

    ee_cert = pki_maker.generate_tls_ee(_ICA_A_KEY_1, pki_maker.RFC9500_INTER_A_KEY_1)

    client = ccadb_client.CcadbClient(
        create_http_client(pems_bytes, entries_bytes), _CURRENT_TIME, True
    )

    issuer_entry = client.find_issuer_entry(ee_cert)
    assert issuer_entry is not None
    assert issuer_entry.cert.subject == _ICA_A_KEY_1.subject


def test_key_rollover_found():
    pems_bytes = write_ccadb_pems([_ICA_A_KEY_1_PEM, _ICA_A_KEY_2_PEM, _ICA_B_PEM])

    entries_bytes = write_ccadb_all_certs(
        [
            {
                "SHA-256 Fingerprint": (
                    _ICA_A_KEY_1.fingerprint(hashes.SHA256()).hex()
                ).upper(),
                "Revocation Status": "Good",
                "Valid To (GMT)": "2025.12.31",
                "Full CRL Issued By This CA": "",
                "JSON Array of Partitioned CRLs": "",
            },
            {
                "SHA-256 Fingerprint": (
                    _ICA_A_KEY_2.fingerprint(hashes.SHA256()).hex()
                ).upper(),
                "Revocation Status": "Good",
                "Valid To (GMT)": "2025.12.31",
                "Full CRL Issued By This CA": "",
                "JSON Array of Partitioned CRLs": "",
            },
            {
                "SHA-256 Fingerprint": (
                    _ICA_B.fingerprint(hashes.SHA256()).hex()
                ).upper(),
                "Revocation Status": "Good",
                "Valid To (GMT)": "2025.12.31",
                "Full CRL Issued By This CA": "",
                "JSON Array of Partitioned CRLs": "",
            },
        ]
    )

    ee_cert = pki_maker.generate_tls_ee(_ICA_A_KEY_2, pki_maker.RFC9500_INTER_A_KEY_2)

    client = ccadb_client.CcadbClient(
        create_http_client(pems_bytes, entries_bytes), _CURRENT_TIME, True
    )

    issuer_entry = client.find_issuer_entry(ee_cert)
    assert issuer_entry is not None
    assert issuer_entry.cert.subject == _ICA_A_KEY_2.subject
