import datetime

import pytest
from cryptography import x509
from dossier import statistics

from dossier.revocation import RevocationClassifier, RevocationWindow
from tests import pki_maker

_CA = pki_maker.generate_inter_a_key_1_ca(pki_maker.generate_root())


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
