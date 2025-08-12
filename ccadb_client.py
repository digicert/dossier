import csv
import logging
import datetime
import httpx
import io

from typing import List, Union
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import Certificate, CertificateRevocationList

logger = logging.getLogger(__name__)

CCADB_TEMPLATE = (
    "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear={year}"
)

class CCADBCertFetcher:
    def __init__(self, http_client: httpx.Client, start_year: int = 1990):
        self.http_client = http_client
        self.start_year = start_year
        self.certs: List[x509.Certificate] = []

    def fetch(self):
        """Fetch certificates from CCADB and store internally."""
        current_year = datetime.datetime.now().year
        for year in range(self.start_year, current_year + 1):
            url = CCADB_TEMPLATE.format(year=year)
            logger.info("Fetching CA certs from %s", url)

            try:
                response = self.http_client.get(url)
                response.raise_for_status()
            except Exception as e:
                logger.error(f"Failed to fetch data for year {year}: {e}")
                continue

            reader = csv.DictReader(io.StringIO(response.text))
            for row in reader:
                pem = row["X.509 Certificate (PEM)"]
                try:
                    cert = x509.load_pem_x509_certificate(pem.encode(), backend=default_backend())
                    self.certs.append(cert)
                except Exception as e:
                    logger.error(f"Failed to parse cert for year {year}: {e}")

    def get_all(self) -> List[x509.Certificate]:
        """Return all fetched certs."""
        return self.certs

    def clear(self):
        """Clear stored certs."""
        self.certs.clear()

    def validate_against_ccadb(self, obj: Union[x509.Certificate, x509.CertificateRevocationList]) -> x509.Certificate:
        """
        Validate that the given certificate or CRL is issued by a CA in the CCADB list.
        Returns the issuer cert if found and valid.
        """
        issuer_name = obj.issuer
        for cert in self.certs:
            if cert.subject == issuer_name:
                try:
                    obj.verify_directly_issued_by(cert)
                    return cert
                except Exception as e:
                    logger.error(f"Issuer found but verification failed with cert key: {e}")
                    # Continue searching other certs
        raise ValueError("Matching issuer certificate not found in CCADB")

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