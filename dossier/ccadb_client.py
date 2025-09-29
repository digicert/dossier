import base64
import collections
import csv
import datetime
import json
import logging
import typing
from typing import List

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import Certificate

logger = logging.getLogger(__name__)

_ALL_ROOTS_INTERMEDIATES_V4_URI = (
    "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4"
)
_CCADB_TEMPLATE = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear={year}"

# first year with valid certificates in CCADB
_PEM_DOWNLOAD_START_YEAR = 1996


class CcadbEntry(typing.NamedTuple):
    cert: x509.Certificate
    key_identifier: bytes
    full_crl_uri: str
    partitioned_crl_uris: List[str]


class CcadbClient:
    def __init__(
        self,
        http_client: httpx.Client,
        current_time: datetime.datetime,
        start_year: int = _PEM_DOWNLOAD_START_YEAR,
    ):
        self._http_client = http_client
        self._start_year = start_year
        self._current_date_str = current_time.strftime("%Y.%m.%d")

        self._ccadb_records_by_fingerprint = self._download_all_records()

        self._issuers_by_name = self._fetch_pems()

    _REVOCATION_STATES = {"Revoked", "Parent Cert Revoked"}

    def _download_all_records(self):
        logger.info(
            "Downloading all Root and Intermediate records from CCADB at %s",
            _ALL_ROOTS_INTERMEDIATES_V4_URI,
        )

        with self._http_client.stream(
            "GET", _ALL_ROOTS_INTERMEDIATES_V4_URI
        ) as response:
            response.raise_for_status()

            return {
                bytes.fromhex(r["SHA-256 Fingerprint"]): r
                for r in csv.DictReader(response.iter_lines())
            }

    def _fetch_pems(self):
        """Fetch certificates from CCADB and store internally."""

        issuers_by_name = collections.defaultdict(list)

        current_year = datetime.datetime.now(tz=datetime.timezone.utc).year

        for year in range(self._start_year, current_year + 1):
            url = _CCADB_TEMPLATE.format(year=year)
            logger.info("Fetching CA data from %s", url)

            with self._http_client.stream("GET", url) as response:
                response.raise_for_status()

                loaded_cert_count = 0

                for idx, row in enumerate(csv.DictReader(response.iter_lines())):
                    pem = row["X.509 Certificate (PEM)"]

                    try:
                        cert = x509.load_pem_x509_certificate(pem.encode())
                    except ValueError:
                        logger.exception(
                            f"Failed to parse cert in CSV row #%d", idx + 1
                        )
                        continue

                    ccadb_entry = self._ccadb_records_by_fingerprint.get(
                        cert.fingerprint(hashes.SHA256())
                    )
                    if ccadb_entry is None:
                        logger.error(
                            f"No CCADB entry found for cert {cert.fingerprint(hashes.SHA256())}"
                        )
                        continue

                    if ccadb_entry["Revocation Status"] in self._REVOCATION_STATES:
                        continue
                    if ccadb_entry["Valid To (GMT)"] < self._current_date_str:
                        continue

                    full_crl_uri_raw = ccadb_entry["Full CRL Issued By This CA"]
                    full_crl_uri = full_crl_uri_raw if full_crl_uri_raw else None

                    partitioned_crl_uris_raw = ccadb_entry[
                        "JSON Array of Partitioned CRLs"
                    ]
                    partitioned_crl_uris = (
                        json.loads(partitioned_crl_uris_raw)
                        if partitioned_crl_uris_raw
                        else None
                    )

                    skid = base64.b64decode(ccadb_entry["Subject Key Identifier"])

                    issuers_by_name[cert.subject.public_bytes()].append(
                        CcadbEntry(cert, skid, full_crl_uri, partitioned_crl_uris)
                    )

                    loaded_cert_count += 1

                logger.info(f"Loaded {loaded_cert_count} valid certs for year {year}")

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
