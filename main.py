import collections
import datetime

from cryptography import x509
import csv
import json
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
parser.add_argument('--format', choices=['csv', 'json'], default='csv', help='Output format (csv or json)')
parser.add_argument('--incident', help="Optional incident discovery datetime in ISO 8601 (e.g. 2025-07-29T15:00:00Z)")

args = parser.parse_args()

all_certs = {}

incident_discovered = None
if args.incident:
    try:
        incident_discovered = datetime.datetime.fromisoformat(args.incident.replace("Z", "+00:00"))
    except ValueError:
        logger.error("Invalid incident datetime format. Use ISO 8601 like '2025-07-29T15:00:00Z'.")
        sys.exit(1)

now = datetime.datetime.now(datetime.timezone.utc)

year_bucket = collections.Counter()

total_certs = 0
revoked_count = 0
expired_without_revocation_count = 0
valid_not_revoked_count = 0
final_without_precert = 0
precert_without_final = 0

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
        total_certs += 1

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
                    revocation_date = ocsp_resp.revocation_time_utc
                    revocation_reason = (
                        ocsp_resp.revocation_reason.name if ocsp_resp.revocation_reason else "unspecified"
                    )

                    if args.incident:
                        incident_time = datetime.datetime.fromisoformat(args.incident.replace("Z", "+00:00"))
                        if revocation_date > incident_time:
                            revocation_status = "Delayed"
                        else:
                            revocation_status = "Yes"
                    else:
                        revocation_status = "Yes"

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

        if revocation_status == 'Yes':
            revoked_count += 1
        elif cert.not_valid_after_utc < now:
            expired_without_revocation_count += 1
        else:
            valid_not_revoked_count += 1

if len(all_certs) >= 10000:
    logger.info("Over 10,000 certificates found. Writing crt.sh links to crtsh_links.txt")

    with open("crtsh_links.txt", "w") as f:
        for cert_entry in all_certs.values():
            fingerprint = cert_entry.get('final_cert_fingerprint_sha256')
            if fingerprint:
                f.write(f"https://crt.sh/?sha256={fingerprint}\n")

for entry in all_certs.values():
    has_final = "final_cert_fingerprint_sha256" in entry
    has_precert = "precert_fingerprint_sha256" in entry

    if has_final and not has_precert:
        final_without_precert += 1
    elif has_precert and not has_final:
        precert_without_final += 1

if args.format == 'csv':
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
else:
    output_list = []
    for serial_number, cert_entry in sorted(all_certs.items(), key=lambda x: x[1]['not_before'], reverse=True):
        cert_entry_with_serial = {'serial_number': serial_number, **cert_entry}
        output_list.append(cert_entry_with_serial)

    json.dump(output_list, sys.stdout, indent=2)
    sys.stdout.write('\n')

sys.stderr.write("\nSummary:\n")
sys.stderr.write(f'{year_bucket}\n')
sys.stderr.write(f"Total Certs: {total_certs}\n")
sys.stderr.write(f"Revoked: {revoked_count}\n")
sys.stderr.write(f"Expired without revocation: {expired_without_revocation_count}\n")
sys.stderr.write(f"Still valid & not revoked: {valid_not_revoked_count}\n")
sys.stderr.write(f"Final cert without precert: {final_without_precert}\n")
sys.stderr.write(f"Precert without final cert: {precert_without_final}\n")