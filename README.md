# dossier
A utility to analyze PEM-encoded X.509 certificates and generate revocation and metadata reports in CSV or JSON format.

# Usage
CSV Output (default)
```bash
python main.py sample_data.csv > sample_data_output.csv
```

JSON Output
Use the <b>--format flag</b> to specify output format
```bash
python main.py sample_data.csv --format json > sample_data_output.json
```

- CSV: Easy to paste into Bugzilla or reports
- JSON: Useful for integration with tools or scripts

# crt.sh Link Generation
If more than 10,000 certificates are processed:
- A separate file named crtsh_links.txt is created
- It contains a list of crt.sh URLs for each certificate

Example output:
```bash
https://crt.sh/?sha256=abcd1234...
https://crt.sh/?sha256=efgh5678...
```