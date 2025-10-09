# Dossier

[![PyPI](https://img.shields.io/pypi/v/dossier)](https://pypi.org/project/dossier)
[![Python Versions](https://img.shields.io/pypi/pyversions/dossier)](https://pypi.org/project/dossier/)
[![Build status](https://github.com/digicert/dossier/actions/workflows/ci_cd_pipeline.yml/badge.svg)](https://github.com/digicert/dossier/actions/workflows/ci_cd_pipeline.yml)
[![GitHub license](https://img.shields.io/pypi/l/dossier)](https://raw.githubusercontent.com/digicert/dossier/main/LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Dossier is an application that generates certificate reports that conform to the format specified in the
[CCADB Incident Reporting Guidelines](https://www.ccadb.org/cas/incident-report). The application accepts individual
PEM- or DER-encoded certificate files, CSV files containing PEM-encoded certificates, or ZIP archives containing
certificate files in any of these formats. The application then reads the certificates, fetches CRL-based revocation
status, and generates a full CSV-formatted report or a summarized crt.sh link list, depending on the number of certificates.

## Installation

1. Python 3.10 or newer must be installed. Python can be downloaded and installed from https://www.python.org/downloads/, or use your operating system's package manager. 
2. To ensure that package dependencies for Dossier do not conflict with globally installed packages on your machine, it is
recommended that you use [pipx](https://pypa.github.io/pipx/) to create a separate Python environment for Dossier. Follow
the instructions on the [pipx homepage](https://pypa.github.io/pipx/) to install pipx.

3. Use pipx to install Dossier:

    ```shell
    pipx install dossier
    ```

Once installed, the bundled command line application will be available on your machine.


## Usage

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

- `--revocation-window` [Optional]
  - Specifies the maximum allowed time between the discovery of an incident and the certificate revocation, when used with the `--incident argument`.
  - Can be 24h, 5d, or 7d 
  - Default is 24h
  - All delay comparisons use that dynamic window

---


## Bugs?

If you find a bug or other issue with Dossier, please create a GitHub issue.

## Contributing

As we intend for this project to be an ecosystem resource, we welcome contributions. It is preferred that proposals for new
features be filed as GitHub issues so that design decisions, etc. can be discussed before submitting a pull request.

This project uses [Black](https://github.com/psf/black) code formatter. The CI/CD pipeline checks for compliance with
this format, so please ensure that any code contributions follow this format.

## Acknowledgements

Dossier is built on several open source packages. In particular, these packages are dependencies of this project:

| Name               | License                                 | Author                                                         | URL                                               |
|--------------------|-----------------------------------------|----------------------------------------------------------------|---------------------------------------------------|
| cryptography       | Apache Software License; BSD License    | The Python Cryptographic Authority and individual contributors | https://github.com/pyca/cryptography              |
| httpx              | BSD 3-Clause "New" or "Revised" License | Encode OSS Ltd.                                                | https://github.com/encode/httpx                   |
| python-dateutil    | Apache Software License; BSD License    | Gustavo Niemeyer                                               | https://github.com/dateutil/dateutil              |
| tqdm               | MIT License                             | tqdm contributors                                              | https://github.com/tqdm/tqdm                      |

The Dossier maintainers are grateful to the authors of these open source contributions.
