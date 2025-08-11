import csv
import logging
import datetime
import httpx
import io

from typing import List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import Certificate

logger = logging.getLogger(__name__)

CCADB_TEMPLATE = (
    "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear={year}"
)

class CCADBCertFetcher:
    def __init__(self, start_year: int = 1990, timeout: int = 5):
        self.start_year = start_year
        self.timeout = timeout
        self.certs: List[x509.Certificate] = []

    def fetch(self):
        """Fetch certificates from CCADB and store internally."""
        current_year = datetime.datetime.now().year
        for year in range(self.start_year, current_year + 1):
            url = CCADB_TEMPLATE.format(year=year)
            logger.info("Fetching CA certs from %s", url)

            try:
                response = httpx.get(url, timeout=self.timeout)
                response.raise_for_status()
            except Exception as e:
                logger.error(f"Failed to fetch data for year {year}: {e}")
                continue

            reader = csv.DictReader(io.StringIO(response.text))
            for row in reader:
                pem = row.get("X.509 Certificate (PEM)")
                try:
                    cert = x509.load_pem_x509_certificate(pem.encode())
                    self.certs.append(cert)
                except Exception as e:
                    logger.warning(f"Failed to parse cert for year {year}: {e}")

    def get_all(self) -> List[x509.Certificate]:
        """Return all fetched certs."""
        return self.certs

    def clear(self):
        """Clear stored certs."""
        self.certs.clear()


def find_issuer_cert_from_ccadb(
    target_cert: Certificate,
    certs: List[Certificate]
) -> Certificate:
    """
    Find the issuer cert in `certs` that actually signed `target_cert`.
    """
    for cert in certs:
        # First filter: subject name match
        if cert.subject != target_cert.issuer:
            continue
        # Second filter: verify cryptographic signature
        try:
            target_cert.verify_directly_issued_by(cert)
            return cert
        except Exception:
            # Not the real issuer, even though subject matches
            continue

    raise ValueError("Matching issuer certificate not found.")