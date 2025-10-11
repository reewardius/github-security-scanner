# GitHub Security Scanner with TruffleHog

A powerful Python tool for discovering exposed secrets and sensitive information across GitHub repositories using keyword-based searches and TruffleHog scanning.

**Install Python Dependencies**
```
pip install requests pandas openpyxl
```
**Install TruffleHog**
```
# Using installation script
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Verify TruffleHog installation:
trufflehog --version
```


**Usage**
```
python3 github_search_v7.py -h

usage: github_search_v7.py [-h] (-k KEYWORD | -kf KEYWORDS_FILE) [-t TOKEN] [-o OUTPUT] [--max-size MAX_SIZE] [--issues] [--xlsx]

GitHub search + TruffleHog scan

optional arguments:
  -h, --help            show this help message and exit
  -k KEYWORD, --keyword KEYWORD
                        Single keyword to search
  -kf KEYWORDS_FILE, --keywords-file KEYWORDS_FILE
                        File with keywords (one per line)
  -t TOKEN, --token TOKEN
                        GitHub API token
  -o OUTPUT, --output OUTPUT
                        Output file for results (CSV or XLSX)
  --max-size MAX_SIZE   Max repo size in MB (default: 500MB)
  --issues              Search only in GitHub issues instead of code
  --xlsx                Save results to Excel (XLSX) instead of CSV
```

**Example 1: Scan for API Keys**
```
python github-security-scanner.py -k "api_key" -t ghp_xxxxx --xlsx -o api_keys_scan.xlsx
```
**Example 2: Multiple Keywords from File**
```
python github-security-scanner.py -kf keywords.txt -t ghp_xxxxx --max-size 200

# keywords.txt

password
api_key
secret_token
aws_access_key
private_key
```
**Example 3: Size Filtering**

Skip repositories larger than specified size (in MB):
```
python github_search_v7.py -k "password" -t YOUR_TOKEN --max-size 100
```

**Example 4: Search Github Issues for Data Leaks**
```
python github-security-scanner.py -k "credentials leaked" -t ghp_xxxxx --issues --xlsx
```
**Example 5: Quick Scan Without Token (Limited)**
```bash
python github-security-scanner.py -k "database_password"
```
Note: Without a token, you're limited to 60 requests/hour

**Console Output:**
```
[INFO] Total repositories scanned: 45
[INFO] Repositories/issues with matched secrets: 12
[SECRET] Repo: https://github.com/user/repo | Detector: AWS | File: config.py:23 | Secret: AKIA...
[WARN] Skipping repo (too large 850.50 MB > 500 MB): https://github.com/large/repo
```






