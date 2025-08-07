import csv
import logging
import datetime
import httpx
from typing import List
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

CCADB_TEMPLATE = (
    "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear={year}"
)

def fetch_ca_certs_from_ccadb(start_year: int = 1990) -> List[x509.Certificate]:
    current_year = datetime.datetime.now().year
    all_certs = []

    for year in range(start_year, current_year + 1):
        url = CCADB_TEMPLATE.format(year=year)
        logger.info("Fetching CA certs from %s", url)
        
        try:
            response = httpx.get(url, timeout=5)
            response.raise_for_status()
        except Exception as e:
            logger.warning(f"Failed to fetch data for year {year}: {e}")
            continue

        csv_text = response.text
        reader = csv.DictReader(csv_text.splitlines())

        for row in reader:
            pem = row.get("X.509 Certificate (PEM)")
            if pem:
                try:
                    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())
                    all_certs.append(cert)
                except Exception as e:
                    logger.debug(f"Failed to parse certificate for year {year}: {e}")

    logger.info(f"Total certs parsed from CCADB: {len(all_certs)}")
    return all_certs


def find_issuer_cert_from_ccadb(issuer_name: x509.Name, certs: List[x509.Certificate]) -> x509.Certificate:
    for cert in certs:
        if cert.subject == issuer_name:
            return cert
    raise ValueError("Matching issuer certificate not found.")