import pytest
import subprocess
from pathlib import Path

from cryptography import x509

from dossier import revocation
from dossier.revocation import RevocationWindow

TEST_CERTS_DIR = Path(__file__).parent / "test_certs"
INCIDENT_DATE = "2025-07-15T03:17:13Z"


# @pytest.mark.parametrize(
#     "cert_file, expected_status",
#     [
#         ("expired_cert.pem", "N/A"),
#         ("revoked_cert.pem", "Yes"),
#         ("revoked_slow_cert.pem", "Delayed"),
#         ("valid_cert.pem", "Planned"),
#     ],
# )
# def test_cert_status(cert_file, expected_status):
#     with open(TEST_CERTS_DIR / cert_file, "rb") as f:
#         pem = f.read()
#
#     cert = x509.load_pem_x509_certificate(pem)
#
#     classifier = revocation.RevocationClassifier(
#         RevocationWindow.TWENTY_FOUR_HOURS,
#         INCIDENT_DATE,
#     )
#
#     result = subprocess.run(
#         ["dossier", "--incident", INCIDENT_DATE, str(cert_path)],
#         capture_output=True,
#         text=True,
#     )
#     output = result.stdout + result.stderr
#     assert expected_status in output, f"No revocation status found in output:\n{output}"
