# Dossier

[![PyPI](https://img.shields.io/pypi/v/cert-dossier)](https://pypi.org/project/cert-dossier)
[![Python Versions](https://img.shields.io/pypi/pyversions/cert-dossier)](https://pypi.org/project/cert-dossier/)
[![Build status](https://github.com/digicert/dossier/actions/workflows/ci_cd_pipeline.yml/badge.svg)](https://github.com/digicert/dossier/actions/workflows/ci_cd_pipeline.yaml)
[![GitHub license](https://img.shields.io/pypi/l/cert-dossier)](https://raw.githubusercontent.com/digicert/dossier/main/LICENSE)
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
    pipx install cert-dossier
    ```

Once installed, the bundled command line application will be available on your machine.

## Usage

### Required Arguments

Dossier requires several arguments to be supplied:

1. `incident_discovery_datetime`: The ISO 8601 timestamp when the incident was discovered. This is used to determine if a certificate was revoked in a timely manner. Documentation for the expected format can be found [here](https://dateutil.readthedocs.io/en/stable/parser.html#dateutil.parser.isoparse). Example: `20250729T150000Z`
2. `revocation_window`: The maximum allowed time between the discovery of an incident and the certificate revocation. Allowed values are `24H`, `5D`, or `7D`.
3. `input_files`: One or more paths to files containing certificates. These paths can be for CSV files, PEM and DER files, or a ZIP file containing these types of files.

There are a few caveats to note regarding the `input_files` argument:

1. File extensions are used to determine the file type. Supported extensions are `.csv`, `.pem`, `.cer`, `.crt`, `.der`, and `.zip`. This behavior may change in the future to instead use magic numbers to determine the file type.
2. CSV files must contain a column named `PEM` or `pem` that contains PEM-encoded certificates. Other columns in the CSV file are ignored.
3. Concatenated PEM files are (currently) not supported.

### Optional Arguments

The following optional arguments can be supplied:

1. `--full-report-threshold`: The maximum number of certificates to process before switching to generating a crt.sh link list instead of a full report. Default is `10000`.
2. `--hide-progress`: If specified, the progress bar will not be displayed during processing.
3. `--output-file`: The path to the output file. If not specified, output will be printed to standard output.
4. `--log-file`: The path to a log file. If not specified, logs will be printed to standard error.
5. `--log-level`: The logging level. Allowed values are `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`. Default is `INFO`.

### Example Invocations

1. Generate a report for an incident discovered on 2025-07-29 at 15:00:00 UTC with a 24-hour revocation window with certificates in `cert1.pem`, `cert2.cer`, and `certs.zip`, printing the report to standard output without displaying a progress bar:

    ```shell
    dossier 20250729T150000Z 24H cert1.pem cert2.cer certs.zip --hide-progress
    ```

2. Generate a report for an incident discovered on 2025-07-29 at 15:00:00 UTC with a 5-day revocation window with certificates in `certs.csv`, writing the report to `report.csv` and logging debug information to `dossier.log`:

    ```shell
    dossier 20250729T150000Z 5D certs.csv --output-file report.csv --log-file dossier.log --log-level DEBUG
    ```

## Processing

Once the required and optional arguments are supplied, Dossier will process the input files and generate a report. The processing steps are as follows:

1. Fetch [V4 All Certificate Information (root and intermediate) in CCADB (CSV)](https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4).
2. Fetch `AllCertificatePEMsCSVFormat` for each year from 1996 (the earliest year that a valid certificate exists) up to and including the current year.
3. Read in the supplied input files and extract certificates.
4. For each certificate, fetch CRL-based revocation status by determining the issuer of the certificate and downloading the relevant CRL(s) using the CRL URI(s) disclosed in CCADB.
5. Using the incident discovery date/time, revocation window, and revocation status, determine the revocation status (expired, timely revoked, delayed revocation, valid but planned to be revoked).
6. Output statistics as a series of INFO-level log messages, which provide comprehensive information about the certificates processed.
7. Generate a report in CSV format or a crt.sh link list, depending on the number of certificates processed and the value of the `--full-report-threshold` option.

## Some Notes on the Full Report Format

The CCADB Incident Reporting Guidelines provide a rigorous format for the full report. However, some design decisions were made in the implementation of Dossier that may not be immediately obvious. These decisions are documented here for clarity:

1. All end-entity S/MIME certificates (those with an Extended Key Usage of `emailProtection`) have their `Subject` listed as `REDACTED`, as these certificates (almost) always contain personal information such as email addresses or names.
2. A space is used to delimit SHA-256 hashes and DNS names.
3. The string representation of subject and issuer DNs is generated using the `rfc4514_string()` method from the `cryptography` package. The use of short names or the "raw" OID format may change depending on the version of the `cryptography` package installed.

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
