import csv
import datetime
import io
import os
import tempfile
import typing
from typing import List

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes

from dossier import ccadb_client, revocation, processor, statistics

from tests import pki_maker, ccadb_utils


@pytest.fixture(autouse=True)
def reset_statistics():
    statistics.INSTANCE.reset()
    yield
    statistics.INSTANCE.reset()


_ROOT_CERT = pki_maker.generate_root()
_ICA_CERT_A_KEY_1 = pki_maker.generate_inter_a_key_1_ca(_ROOT_CERT)
_ICA_CERT_B = pki_maker.generate_inter_b_ca(_ROOT_CERT)

_CURRENT_TIME = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)


def _create_ccadb_entry(cert):
    return {
        "SHA-256 Fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "Revocation Status": "Not Revoked",
        "Valid To (GMT)": "9999.12.31",
        "Full CRL Issued By This CA": "http://ca.example/crls/full.crl",
        "JSON Array of Partitioned CRLs": "",
    }


_CCADB_CLIENT = ccadb_client.CcadbClient(
    ccadb_utils.create_http_client(
        ccadb_utils.write_ccadb_pems(
            [
                c.public_bytes(serialization.Encoding.PEM)
                for c in (_ICA_CERT_A_KEY_1, _ICA_CERT_B)
            ]
        ),
        ccadb_utils.write_ccadb_all_certs(
            [
                _create_ccadb_entry(_ICA_CERT_A_KEY_1),
                _create_ccadb_entry(_ICA_CERT_B),
            ]
        ),
    ),
    _CURRENT_TIME,
    True,
)

_REVOCATION_CLASSIFIER = revocation.RevocationClassifier(
    revocation.RevocationWindow.TWENTY_FOUR_HOURS,
    _CURRENT_TIME - datetime.timedelta(days=1),
    _CURRENT_TIME,
)


def _get_crl_http_client(crl: x509.CertificateRevocationList) -> httpx.Client:
    def handle_request(request: httpx.Request) -> httpx.Response:
        url = str(request.url)

        if url == "http://ca.example/crls/full.crl":
            return httpx.Response(
                200, content=crl.public_bytes(serialization.Encoding.DER)
            )
        else:
            return httpx.Response(404, content=b"")

    return httpx.Client(transport=httpx.MockTransport(handle_request))


def _create_revocation_manager(crl_http_client):
    return revocation.RevocationManager(
        crl_http_client, _CCADB_CLIENT, _REVOCATION_CLASSIFIER, _CURRENT_TIME
    )


def _create_csv_file(certs: List[x509.Certificate]):
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv") as f:
        writer = csv.writer(f)
        writer.writerow(["PEM"])
        for cert in certs:
            writer.writerow([cert.public_bytes(serialization.Encoding.PEM).decode()])

        file_name = f.name

    return open(file_name, "rb", buffering=0)


def test_duplicate_fingerprint():
    crl = pki_maker.generate_crl(
        _ICA_CERT_A_KEY_1,
        pki_maker.RFC9500_INTER_A_KEY_1,
        [],
    )

    ee = pki_maker.generate_tls_ee(_ICA_CERT_A_KEY_1, pki_maker.RFC9500_INTER_A_KEY_1)

    file = None
    try:
        file = _create_csv_file([ee, ee])

        proc = processor.Processor(_create_revocation_manager(crl), True)
        proc.process_files([file])

        assert statistics.INSTANCE.duplicate_cert_count == 1
    finally:
        if file:
            file_name = file.name

            file.close()
            os.remove(file_name)


def test_redacted_smime():
    crl = pki_maker.generate_crl(
        _ICA_CERT_B,
        pki_maker.RFC9500_INTER_B_KEY,
        [],
    )

    ee = pki_maker.generate_smime_ee(_ICA_CERT_B, pki_maker.RFC9500_INTER_B_KEY)

    file = None
    try:
        file = _create_csv_file([ee])

        proc = processor.Processor(_create_revocation_manager(crl), True)
        entries = proc.process_files([file])

        assert len(entries) == 1
        assert entries[0].subject == "REDACTED"
    finally:
        if file:
            file_name = file.name

            file.close()
            os.remove(file_name)


def test_not_redacted_tls():
    crl = pki_maker.generate_crl(
        _ICA_CERT_B,
        pki_maker.RFC9500_INTER_B_KEY,
        [],
    )

    ee = pki_maker.generate_tls_ee(_ICA_CERT_B, pki_maker.RFC9500_INTER_B_KEY)

    file = None
    try:
        file = _create_csv_file([ee])

        proc = processor.Processor(_create_revocation_manager(crl), True)
        entries = proc.process_files([file])

        assert len(entries) == 1
        assert "REDACTED" not in entries[0].subject

        assert statistics.INSTANCE.final_without_precert == 1
    finally:
        if file:
            file_name = file.name

            file.close()
            os.remove(file_name)


def test_tls_final_duplicate_serial_same_issuer():
    crl = pki_maker.generate_crl(
        _ICA_CERT_A_KEY_1,
        pki_maker.RFC9500_INTER_A_KEY_1,
        [],
    )

    ee1 = pki_maker.generate_tls_ee(
        _ICA_CERT_A_KEY_1, pki_maker.RFC9500_INTER_A_KEY_1, serial_number=1
    )
    ee2 = pki_maker.generate_tls_ee(
        _ICA_CERT_A_KEY_1, pki_maker.RFC9500_INTER_A_KEY_1, serial_number=1
    )

    file = None
    try:
        file = _create_csv_file([ee1, ee2])

        proc = processor.Processor(_create_revocation_manager(crl), True)
        entries = proc.process_files([file])

        assert len(entries) == 1
        assert len(entries[0].final_cert_sha256_hashes) == 2

        assert statistics.INSTANCE.final_without_precert == 1

        # two errors: final without precert, and duplicate serial number
        assert statistics.INSTANCE.error_count == 2
    finally:
        if file:
            file_name = file.name

            file.close()
            os.remove(file_name)


def test_tls_precert_duplicate_serial_same_issuer():
    crl = pki_maker.generate_crl(
        _ICA_CERT_A_KEY_1,
        pki_maker.RFC9500_INTER_A_KEY_1,
        [],
    )

    ee1 = pki_maker.generate_tls_ee(
        _ICA_CERT_A_KEY_1,
        pki_maker.RFC9500_INTER_A_KEY_1,
        serial_number=1,
        is_precert=True,
    )
    ee2 = pki_maker.generate_tls_ee(
        _ICA_CERT_A_KEY_1,
        pki_maker.RFC9500_INTER_A_KEY_1,
        serial_number=1,
        is_precert=True,
    )

    file = None
    try:
        file = _create_csv_file([ee1, ee2])

        proc = processor.Processor(_create_revocation_manager(crl), True)
        entries = proc.process_files([file])

        assert len(entries) == 1
        assert len(entries[0].precert_sha256_hashes) == 2

        assert statistics.INSTANCE.precert_without_final == 1

        # two errors: precert without final, and duplicate serial number
        assert statistics.INSTANCE.error_count == 2
    finally:
        if file:
            file_name = file.name

            file.close()
            os.remove(file_name)
