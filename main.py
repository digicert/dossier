import collections
import datetime

from cryptography import x509
import csv
import argparse
import logging
import sys
import tqdm

from cryptography.hazmat.primitives import hashes
from cryptography.x509 import oid

import naive_ocsp_client

logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger(__name__)


parser = argparse.ArgumentParser()
parser.add_argument('pem_csvs', type=argparse.FileType('r', encoding='utf-8'), nargs='+')

args = parser.parse_args()

all_certs = {}

now = datetime.datetime.now(datetime.timezone.utc)

year_bucket = collections.Counter()

def _get_dnsnames(cert):
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
        return ','.join(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return ''

def _is_precert(cert):
    try:
        cert.extensions.get_extension_for_oid(oid.ExtensionOID.PRECERT_POISON)

        return True
    except x509.ExtensionNotFound:
        return False

for pem_csv in args.pem_csvs:
    logger.info('Parsing %s', pem_csv.name)

    for line_idx, row in tqdm.tqdm(enumerate(csv.DictReader(pem_csv))):
        pem = row.get('pem')
        if not pem:
            logger.error('No PEM found in row #%d: %s', line_idx, row)
            continue

        try:
            cert = x509.load_pem_x509_certificate(pem.encode())
        except ValueError as e:
            logger.error('Failed to parse PEM in row %s: %s', row, e)
            continue

        serial_number = hex(cert.serial_number)[2:]

        cert_entry = all_certs.get(serial_number)
        if cert_entry is None:
            cert_entry = {
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'not_before': cert.not_valid_before_utc.isoformat(),
                'not_after': cert.not_valid_after_utc.isoformat(),
                'dns_names': _get_dnsnames(cert),
            }

            revocation_status = 'N/A'
            revocation_date = 'N/A'
            revocation_reason = 'N/A'
            if cert.not_valid_after_utc >= now:
                ocsp_resp = naive_ocsp_client.naive_fetch(cert)

                is_revoked = ocsp_resp.revocation_time_utc is not None

                if is_revoked:
                    revocation_status = 'Yes'

                    revocation_date = ocsp_resp.revocation_time_utc.isoformat()

                    if ocsp_resp.revocation_reason:
                        revocation_reason = ocsp_resp.revocation_reason.name
                else:
                    revocation_status = 'No'

            cert_entry['revocation_status'] = revocation_status
            cert_entry['revocation_date'] = revocation_date
            cert_entry['revocation_reason'] = revocation_reason

            issued_year = cert.not_valid_before_utc.year
            year_bucket[issued_year] += 1

            all_certs[serial_number] = cert_entry

        fingerprint_key = 'precert_fingerprint_sha256' if _is_precert(cert) else 'final_cert_fingerprint_sha256'
        if fingerprint_key in cert_entry:
            logger.error('Duplicate key "%s" for serial number %s found, overwriting', fingerprint_key, cert.serial_number)

        cert_entry[fingerprint_key] = cert.fingerprint(hashes.SHA256()).hex()

c = csv.writer(sys.stdout, lineterminator='\n')
c.writerow(['Precertificate SHA-256 Hash', 'Certificate SHA-256 Hash', 'Subject', 'Issuer', 'Not before', 'Not after', 'Serial #', 'dNSNames', 'Is Revoked?', 'Revocation Date', 'Revocation Reason'])

for serial_number, cert_entry in sorted(list(all_certs.items()), key=lambda x: x[1]['not_before'], reverse=True):
    if not cert_entry.get('precert_fingerprint_sha256'):
        logger.error('Missing precert_fingerprint_sha256 for serial number %s', serial_number)

    if not cert_entry.get('final_cert_fingerprint_sha256'):
        logger.error('Missing final_cert_fingerprint_sha256 for serial number %s', serial_number)

    c.writerow([
        cert_entry.get('precert_fingerprint_sha256', 'N/A'),
        cert_entry.get('final_cert_fingerprint_sha256', 'N/A'),
        cert_entry['subject'],
        cert_entry['issuer'],
        cert_entry['not_before'],
        cert_entry['not_after'],
        serial_number,
        cert_entry['dns_names'],
        cert_entry['revocation_status'],
        cert_entry['revocation_date'],
        cert_entry['revocation_reason'],
    ])

sys.stderr.write(f'{year_bucket}\n')
