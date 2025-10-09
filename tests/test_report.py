import datetime
import io

from dossier import report, revocation
from dossier.report import CertificateType


def test_link_report_basic():
    entry = report.ReportEntry(
        cert_type=CertificateType.TLS_EE,
        serial_number=123456,
        subject="CN=Test",
        issuer="CN=Issuer",
        not_before=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
        dns_names="example.com,www.example.com",
        revocation_info=revocation.RevocationInfo("N/A", "N/A", "N/A"),
        precert_sha256_hashes=[bytes.fromhex("a" * 64)],
        final_cert_sha256_hashes=[bytes.fromhex("b" * 64)],
    )

    with io.StringIO() as f:
        report.write_link_report([entry], f)
        output = f.getvalue()

        assert ("https://crt.sh/?sha256=" + "a" * 64) in output
        assert ("https://crt.sh/?sha256=" + "b" * 64) in output

        assert hex(123456)[2:] not in output


def test_full_report_basic():
    entry = report.ReportEntry(
        cert_type=CertificateType.TLS_EE,
        serial_number=123456,
        subject="CN=Test",
        issuer="CN=Issuer",
        not_before=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
        dns_names="example.com www.example.com",
        revocation_info=revocation.RevocationInfo("N/A", "N/A", "N/A"),
        precert_sha256_hashes=[bytes.fromhex("a" * 64)],
        final_cert_sha256_hashes=[bytes.fromhex("b" * 64)],
    )

    with io.StringIO() as f:
        report.write_full_report([entry], f)
        output = f.getvalue()

        assert "Precertificate SHA-256 hash" in output
        assert "Certificate SHA-256 hash" in output
        assert "Subject" in output
        assert "Issuer" in output
        assert "Not before" in output
        assert "Not after" in output
        assert "Serial #" in output
        assert "dNSNames" in output
        assert "Is revoked?" in output
        assert "Revocation date" in output
        assert "Revocation reason" in output

        assert ("a" * 64) in output
        assert ("b" * 64) in output

        assert hex(123456)[2:] in output
        assert "CN=Test" in output
        assert "CN=Issuer" in output
        assert "2024-01-01T00:00:00+00:00" in output
        assert "2025-01-01T00:00:00+00:00" in output
        assert "example.com www.example.com" in output
        assert "N/A" in output
