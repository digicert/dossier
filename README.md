# Dossier

A Python package for processing X.509 certificates and validating their revocation status using OCSP.

## Features

- **Multiple Input Formats**: Process certificates from CSV files, directories, or ZIP archives
- **OCSP Validation**: Check certificate revocation status using OCSP responders
- **Flexible Output**: Generate reports in CSV or JSON format
- **Bulk Processing**: Handle thousands of certificates efficiently
- **Progress Tracking**: Visual progress bars for large datasets
- **Library & CLI**: Use as a command-line tool or import as a Python library
- **CCADB Integration**: Fetch trusted CA certificates directly from Mozilla's CCADB
- **Certificate & CRL Validation**: Verify if a certificate or CRL is issued by a CA in the CCADB
- **Pluggable HTTP Client**: Inject custom httpx.Client instances for retries, timeouts, or testing

## Installation

### From Source
```bash
git clone https://github.com/digicert/dossier.git
cd dossier
pip install -e .
```

### For Development
```bash
git clone https://github.com/digicert/dossier.git
cd dossier
pip install -e .[dev]
```

## Command Line Usage

After installation, use the `dossier` command:

### CSV Output (default)
```bash
# CSV file input
dossier sample_data.csv > sample_data_output.csv

# Directory input  
dossier tests/pems_dir > directory_output.csv

# ZIP file input
dossier tests/pems_zipped.zip > zip_output.csv
```

### JSON Output
```bash
# CSV file input
dossier sample_data.csv --format json > sample_data_output.json

# Directory input
dossier tests/pems_dir --format json > directory_output.json

# ZIP file input
dossier tests/pems_zipped.zip --format json > zip_output.json
```

## Library Usage

```python
from dossier import load_certs_from_directory, load_cert_from_file
from dossier.main import process_cert_list

# Load certificates from a directory (generator for memory efficiency)
for cert_info in load_certs_from_directory('/path/to/certs'):
    print(f"Loaded: {cert_info['source']}")
    # Process individual certificate...

# Load a single certificate
cert = load_cert_from_file('/path/to/cert.pem')

# Load all certificates into a list (for smaller datasets)
from dossier import load_certs_from_directory_list
cert_list = load_certs_from_directory_list('/path/to/certs')
```

## Input Types

The tool supports multiple input formats:

1. **CSV files** - Files containing PEM certificates in a `pem` column
2. **Directories** - Folders containing multiple `.pem` files  
3. **ZIP files** - Compressed archives containing `.pem` files
4. **Single PEM files** - Individual certificate files

## Output Formats

- **CSV**: Easy to import into spreadsheets or paste into reports
- **JSON**: Structured data for integration with other tools

# Link Generation
If more than 10,000 certificates are processed:
- A separate file named crtsh_links.txt is created
- It contains a list of crt.sh URLs for each certificate

Example output:
```bash
https://crt.sh/?sha256=abcd1234...
https://crt.sh/?sha256=efgh5678...
```

# Incident Discovery
Optionally provide an incident discovery datetime using the `--incident` parameter. This allows the script to adjust the **Revocation Status** field based on when the incident was discovered relative to the certificate's revocation time.

### Behavior

- If `--incident` is provided with a valid ISO 8601 datetime (e.g., `"2025-07-29T15:00:00Z"`):
  - If the incident discovery time is **more than 24 hours after** the certificate revocation time, the **Revocation Status** will be set to `"Delayed"`.
  - If the incident discovery time is **within 24 hours** of the revocation time, the **Revocation Status** will be `"Yes"`.
  - If the certificate is expired, the status will be `"N/A"` regardless of incident time.

---

## Usage

```bash
dossier sample_data.csv --format csv > sample_data_output.csv