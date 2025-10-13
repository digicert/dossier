import datetime
import json

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import ReasonFlags

from dossier import statistics, revocation, ccadb_client

from dossier.revocation import RevocationClassifier, RevocationWindow
from tests import pki_maker, ccadb_utils

_CA = pki_maker.generate_inter_a_key_1_ca(pki_maker.generate_root())

_ROOT_CERT = pki_maker.generate_root()
_ICA_CERT_A_KEY_1 = pki_maker.generate_inter_a_key_1_ca(_ROOT_CERT)
_ICA_CERT_B = pki_maker.generate_inter_b_ca(_ROOT_CERT)

_CURRENT_TIME = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)


def _create_ccadb_entry(cert, partitioned_crl=False):
    return {
        "SHA-256 Fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "Revocation Status": "Not Revoked",
        "Valid To (GMT)": "9999.12.31",
        "Full CRL Issued By This CA": (
            "" if partitioned_crl else "http://ca.example/crls/crl.crl"
        ),
        "JSON Array of Partitioned CRLs": (
            json.dumps(["http://ca.example/crls/crl.crl"]) if partitioned_crl else ""
        ),
    }


_CCADB_CLIENT = ccadb_client.CcadbClient(
    ccadb_utils.create_http_client(
        ccadb_utils.write_ccadb_pems(
            [_ICA_CERT_A_KEY_1.public_bytes(serialization.Encoding.PEM).decode()]
        ),
        ccadb_utils.write_ccadb_all_certs(
            [
                _create_ccadb_entry(_ICA_CERT_A_KEY_1),
            ]
        ),
    ),
    _CURRENT_TIME,
    True,
)


def _get_crl_http_client(crl: x509.CertificateRevocationList) -> httpx.Client:
    def handle_request(request: httpx.Request) -> httpx.Response:
        url = str(request.url)

        if url == "http://ca.example/crls/crl.crl":
            return httpx.Response(
                200, content=crl.public_bytes(serialization.Encoding.DER)
            )
        else:
            return httpx.Response(404, content=b"")

    return httpx.Client(transport=httpx.MockTransport(handle_request))


def _generate_crl_entry(
    serial_number: int, revocation_date: datetime.datetime
) -> x509.RevokedCertificate:
    crl = pki_maker.generate_crl(
        _CA, pki_maker.RFC9500_INTER_A_KEY_1, [(serial_number, revocation_date, None)]
    )

    return crl.get_revoked_certificate_by_serial_number(serial_number)


@pytest.fixture(autouse=True)
def reset_statistics():
    statistics.INSTANCE.reset()
    yield
    statistics.INSTANCE.reset()


def test_delayed():
    classifier = RevocationClassifier(
        RevocationWindow.SEVEN_DAYS,
        datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 1, 10, tzinfo=datetime.timezone.utc),
    )

    revoked_cert = _generate_crl_entry(
        1, datetime.datetime(2024, 1, 9, tzinfo=datetime.timezone.utc)
    )

    assert classifier.classify_revocation(revoked_cert) == "Delayed"
    assert statistics.INSTANCE.delayed_revoked_cert_count == 1
    assert statistics.INSTANCE.valid_cert_count == 0


def test_planned_delayed():
    classifier = RevocationClassifier(
        RevocationWindow.SEVEN_DAYS,
        datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 1, 10, tzinfo=datetime.timezone.utc),
    )

    assert classifier.classify_revocation(None) == "Planned"
    assert statistics.INSTANCE.delayed_valid_cert_count == 1
    assert statistics.INSTANCE.valid_cert_count == 1


def test_revoked_timely():
    classifier = RevocationClassifier(
        RevocationWindow.SEVEN_DAYS,
        datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 1, 5, tzinfo=datetime.timezone.utc),
    )

    revoked_cert = _generate_crl_entry(
        1, datetime.datetime(2024, 1, 3, tzinfo=datetime.timezone.utc)
    )

    assert classifier.classify_revocation(revoked_cert) == "Yes"
    assert statistics.INSTANCE.timely_revoked_cert_count == 1
    assert statistics.INSTANCE.valid_cert_count == 0


def test_revoked_delayed_5_days_one_second():
    classifier = RevocationClassifier(
        RevocationWindow.FIVE_DAYS,
        datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 1, 6, second=1, tzinfo=datetime.timezone.utc),
    )

    revoked_cert = _generate_crl_entry(
        1, datetime.datetime(2024, 1, 6, second=1, tzinfo=datetime.timezone.utc)
    )

    assert classifier.classify_revocation(revoked_cert) == "Delayed"
    assert statistics.INSTANCE.delayed_revoked_cert_count == 1
    assert statistics.INSTANCE.valid_cert_count == 0


def test_revoked_timely_5_days():
    classifier = RevocationClassifier(
        RevocationWindow.FIVE_DAYS,
        datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 1, 6, tzinfo=datetime.timezone.utc),
    )

    revoked_cert = _generate_crl_entry(
        1, datetime.datetime(2024, 1, 6, tzinfo=datetime.timezone.utc)
    )

    assert classifier.classify_revocation(revoked_cert) == "Yes"
    assert statistics.INSTANCE.timely_revoked_cert_count == 1
    assert statistics.INSTANCE.valid_cert_count == 0


def test_revocation_manager_issuer_not_found():
    classifier = revocation.RevocationClassifier(
        revocation.RevocationWindow.TWENTY_FOUR_HOURS,
        _CURRENT_TIME - datetime.timedelta(days=1),
        _CURRENT_TIME,
    )

    manager = revocation.RevocationManager(
        _get_crl_http_client(
            pki_maker.generate_crl(
                _ICA_CERT_A_KEY_1, pki_maker.RFC9500_INTER_A_KEY_1, []
            )
        ),
        _CCADB_CLIENT,
        classifier,
        _CURRENT_TIME,
    )

    cert = pki_maker.generate_tls_ee(_ICA_CERT_B, pki_maker.RFC9500_INTER_B_KEY)

    info = manager.get_revocation_info(cert)
    assert info.status == "N/A"
    assert info.date == "N/A"
    assert info.reason == "N/A"

    assert statistics.INSTANCE.error_count == 1


def test_revocation_manager_expired_cert():
    classifier = revocation.RevocationClassifier(
        revocation.RevocationWindow.TWENTY_FOUR_HOURS,
        _CURRENT_TIME - datetime.timedelta(days=1),
        _CURRENT_TIME,
    )

    future_date = _CURRENT_TIME + datetime.timedelta(days=365)

    manager = revocation.RevocationManager(
        _get_crl_http_client(
            pki_maker.generate_crl(
                _ICA_CERT_A_KEY_1,
                pki_maker.RFC9500_INTER_A_KEY_1,
                [],
                None,
                future_date,
            )
        ),
        _CCADB_CLIENT,
        classifier,
        future_date,
    )

    cert = pki_maker.generate_tls_ee(_ICA_CERT_A_KEY_1, pki_maker.RFC9500_INTER_A_KEY_1)

    info = manager.get_revocation_info(cert)
    assert info.status == "N/A"
    assert info.date == "N/A"
    assert info.reason == "N/A"

    assert statistics.INSTANCE.expired_cert_count == 1


def test_revocation_manager_revoked():
    classifier = revocation.RevocationClassifier(
        revocation.RevocationWindow.TWENTY_FOUR_HOURS,
        _CURRENT_TIME - datetime.timedelta(days=1),
        _CURRENT_TIME,
    )

    cert = pki_maker.generate_tls_ee(_ICA_CERT_A_KEY_1, pki_maker.RFC9500_INTER_A_KEY_1)

    manager = revocation.RevocationManager(
        _get_crl_http_client(
            pki_maker.generate_crl(
                _ICA_CERT_A_KEY_1,
                pki_maker.RFC9500_INTER_A_KEY_1,
                [(cert.serial_number, _CURRENT_TIME, x509.ReasonFlags.key_compromise)],
            )
        ),
        _CCADB_CLIENT,
        classifier,
        _CURRENT_TIME,
    )

    info = manager.get_revocation_info(cert)
    assert info.status == "Yes"
    assert info.date == _CURRENT_TIME.isoformat()
    assert info.reason == x509.ReasonFlags.key_compromise.name

    assert statistics.INSTANCE.timely_revoked_cert_count == 1
    assert (
        statistics.INSTANCE.cert_count_by_revocation_reason_code[
            x509.ReasonFlags.key_compromise.name
        ]
        == 1
    )


def test_revocation_manager_revoked_no_reason_code():
    classifier = revocation.RevocationClassifier(
        revocation.RevocationWindow.TWENTY_FOUR_HOURS,
        _CURRENT_TIME - datetime.timedelta(days=1),
        _CURRENT_TIME,
    )

    cert = pki_maker.generate_tls_ee(_ICA_CERT_A_KEY_1, pki_maker.RFC9500_INTER_A_KEY_1)

    manager = revocation.RevocationManager(
        _get_crl_http_client(
            pki_maker.generate_crl(
                _ICA_CERT_A_KEY_1,
                pki_maker.RFC9500_INTER_A_KEY_1,
                [(cert.serial_number, _CURRENT_TIME, None)],
            )
        ),
        _CCADB_CLIENT,
        classifier,
        _CURRENT_TIME,
    )

    info = manager.get_revocation_info(cert)
    assert info.status == "Yes"
    assert info.date == _CURRENT_TIME.isoformat()
    assert info.reason == "N/A"

    assert statistics.INSTANCE.timely_revoked_cert_count == 1
    assert all(c == 0 for c in statistics.INSTANCE.cert_count_by_revocation_reason_code)


def test_revocation_manager_revoked_partitioned():
    ccadb = ccadb_client.CcadbClient(
        ccadb_utils.create_http_client(
            ccadb_utils.write_ccadb_pems(
                [_ICA_CERT_A_KEY_1.public_bytes(serialization.Encoding.PEM).decode()]
            ),
            ccadb_utils.write_ccadb_all_certs(
                [
                    _create_ccadb_entry(_ICA_CERT_A_KEY_1, True),
                ]
            ),
        ),
        _CURRENT_TIME,
        True,
    )

    classifier = revocation.RevocationClassifier(
        revocation.RevocationWindow.TWENTY_FOUR_HOURS,
        _CURRENT_TIME - datetime.timedelta(days=1),
        _CURRENT_TIME,
    )

    cert = pki_maker.generate_tls_ee(_ICA_CERT_A_KEY_1, pki_maker.RFC9500_INTER_A_KEY_1)

    manager = revocation.RevocationManager(
        _get_crl_http_client(
            pki_maker.generate_crl(
                _ICA_CERT_A_KEY_1,
                pki_maker.RFC9500_INTER_A_KEY_1,
                [(cert.serial_number, _CURRENT_TIME, ReasonFlags.key_compromise)],
                idp_uri="http://ca.example/crls/crl.crl",
            )
        ),
        ccadb,
        classifier,
        _CURRENT_TIME,
    )

    info = manager.get_revocation_info(cert)
    assert info.status == "Yes"
    assert info.date == _CURRENT_TIME.isoformat()
    assert info.reason == ReasonFlags.key_compromise.name

    assert statistics.INSTANCE.timely_revoked_cert_count == 1
