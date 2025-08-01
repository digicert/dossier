# dossier
This script parses PEM certificates from CSV files, checks their revocation status using OCSP, and outputs a report in CSV or JSON format.

# Usage
CSV Output (default)
```bash
python main.py sample_data.csv > sample_data_output.csv
```

JSON Output<br>
Use the `--format flag` to specify output format
```bash
python main.py sample_data.csv --format json > sample_data_output.json
```

- CSV: Easy to paste into Bugzilla or reports
- JSON: Useful for integration with tools or scripts

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
python main.py sample_data.csv --format csv > sample_data_output.csv