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

        assert "01e240" in output  # 123456 → 3 bytes → 01e240 (leading zero preserved)
        assert "CN=Test" in output
        assert "CN=Issuer" in output
        assert "2024-01-01T00:00:00+00:00" in output
        assert "2025-01-01T00:00:00+00:00" in output
        assert "example.com www.example.com" in output


def test_full_report_serial_leading_zero():
    """Serial numbers whose first nibble is 0 must not have it truncated."""
    # 0x0ff00d has bit_length=20 → 3 bytes → should output '0ff00d', not 'ff00d'
    entry = report.ReportEntry(
        cert_type=CertificateType.TLS_EE,
        serial_number=0x0FF00D,
        subject="CN=Test",
        issuer="CN=Issuer",
        not_before=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
        dns_names="example.com",
        revocation_info=revocation.RevocationInfo("N/A", "N/A", "N/A"),
        precert_sha256_hashes=[],
        final_cert_sha256_hashes=[bytes.fromhex("c" * 64)],
    )

    with io.StringIO() as f:
        report.write_full_report([entry], f)
        output = f.getvalue()
        assert "0ff00d" in output
        assert "ff00d" not in output.replace("0ff00d", "")
        assert "N/A" in output
