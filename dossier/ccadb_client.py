import collections
import csv
import datetime
import io
import json
import logging
import typing
from typing import List

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import Certificate

logger = logging.getLogger(__name__)

_CCADB_TEMPLATE = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear={year}"


class CcadbEntry(typing.NamedTuple):
    cert: x509.Certificate
    full_crl_uri: str
    partitioned_crl_uris: List[str]


class CcadbClient:
    def __init__(
        self,
        http_client: httpx.Client,
        current_time: datetime.datetime,
        start_year: int = 1990,
    ):
        self._http_client = http_client
        self._start_year = start_year
        self._current_date_str = current_time.strftime("%Y.%m.%d")

        self._issuers_by_name = self._fetch()

    _REVOCATION_STATES = {"Revoked", "Parent Cert Revoked"}

    def _fetch(self):
        """Fetch certificates from CCADB and store internally."""

        issuers_by_name = collections.defaultdict(list)

        current_year = datetime.datetime.now().year
        for year in range(self._start_year, current_year + 1):
            url = _CCADB_TEMPLATE.format(year=year)
            logger.info("Fetching CA data from %s", url)

            try:
                response = self._http_client.get(url)
                response.raise_for_status()
            except Exception as e:
                logger.error(f"Failed to fetch data for year {year}: {e}")
                continue

            reader = csv.DictReader(io.StringIO(response.text))
            for row in reader:
                if row["Revocation Status"] in self._REVOCATION_STATES:
                    continue
                if row["Valid To (GMT)"] < self._current_date_str:
                    continue

                pem = row["X.509 Certificate (PEM)"]
                try:
                    cert = x509.load_pem_x509_certificate(pem.encode())
                except Exception as e:
                    logger.error(f"Failed to parse cert for year {year}: {e}")
                    continue

                full_crl_uri_raw = row["Full CRL Issued By This CA"]
                full_crl_uri = full_crl_uri_raw if full_crl_uri_raw else None

                partitioned_crl_uris_raw = row["JSON Array of Partitioned CRLs"]
                partitioned_crl_uris = (
                    json.loads(partitioned_crl_uris_raw)
                    if partitioned_crl_uris_raw
                    else None
                )

                issuers_by_name[cert.subject.public_bytes()].append(
                    CcadbEntry(cert, full_crl_uri, partitioned_crl_uris)
                )

        return issuers_by_name

    def find_issuer_entry(self, cert: Certificate) -> typing.Optional[CcadbEntry]:
        """
        Find the issuer that signed `cert`.
        """
        # First filter: subject name match
        matched_issuers = self._issuers_by_name.get(cert.issuer.public_bytes())

        if not matched_issuers:
            return None

        for issuer in matched_issuers:
            # Second filter: verify cryptographic signature
            try:
                cert.verify_directly_issued_by(issuer.cert)

                return issuer
            except InvalidSignature:
                # Not the real issuer, even though the subject matches
                continue

        return None
