#!/usr/bin/env python3
import os
import csv
import subprocess
import requests
import argparse
import shutil
import re
from time import sleep
import pandas as pd

# ======== Аргументы командной строки ========
parser = argparse.ArgumentParser(description="GitHub search + TruffleHog scan")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-k", "--keyword", help="Single keyword to search")
group.add_argument("-kf", "--keywords-file", help="File with keywords (one per line)")
parser.add_argument("-t", "--token", help="GitHub API token")
parser.add_argument("-o", "--output", default=None, help="Output file for results (CSV or XLSX)")
parser.add_argument("--max-size", type=int, default=500, help="Max repo size in MB (default: 500MB)")
parser.add_argument("--issues", action="store_true", help="Search only in GitHub issues instead of code")
parser.add_argument("--xlsx", action="store_true", help="Save results to Excel (XLSX) instead of CSV")
args = parser.parse_args()

# ======== Настройки ========
GITHUB_TOKEN = args.token
RESULT_FILE = args.output if args.output else ("github_trufflehog_results.xlsx" if args.xlsx else "github_trufflehog_results.csv")
PUBLIC_REPOS_FILE = "github_public_repos.xlsx" if args.xlsx else "github_public_repos.csv"
TEMP_DIR = "./temp_repos"
MAX_SIZE_KB = args.max_size * 1024  # KB

# ======== Удаляем старую папку temp_repos ========
if os.path.exists(TEMP_DIR):
    shutil.rmtree(TEMP_DIR)
os.makedirs(TEMP_DIR, exist_ok=True)

HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

# ======== Список ключевых слов ========
if args.keyword:
    SEARCH_KEYWORDS = [args.keyword]
elif args.keywords_file:
    with open(args.keywords_file, "r", encoding="utf-8") as f:
        SEARCH_KEYWORDS = [line.strip() for line in f if line.strip()]

# ======== Вспомогательные функции ========
def print_info(message):
    print(f"[INFO] {message}")

def print_warn(message):
    print(f"[WARN] {message}")

def print_secret(repo_url, detector_type="", file_path="", line_number="", raw_result="", issue_url="", issue_title="", issue_body_snippet=""):
    if issue_url:
        print(f"[ISSUE] URL: {issue_url} | Title: {issue_title} | Snippet: {issue_body_snippet}")
    else:
        print(f"[SECRET] Repo: {repo_url} | Detector: {detector_type} | File: {file_path}:{line_number} | Secret: {raw_result}")

# ======== GitHub Code Search (с пагинацией) ========
def search_github_code_all_pages(keyword):
    results = []
    page = 1
    per_page = 100
    while True:
        url = f"https://api.github.com/search/code?q={keyword}+in:file&per_page={per_page}&page={page}"
        response = requests.get(url, headers=HEADERS)
        if response.status_code != 200:
            print_warn(f"GitHub API Error {response.status_code}: {response.text}")
            break
        data = response.json()
        items = data.get("items", [])
        if not items:
            break
        results.extend(items)
        if len(items) < per_page:
            break
        page += 1
        sleep(1)
    return results

# ======== GitHub Issues Search (с пагинацией) ========
def search_github_issues_all_pages(keyword):
    results = []
    page = 1
    per_page = 100
    while True:
        url = f"https://api.github.com/search/issues?q={keyword}+in:title,body+is:issue&per_page={per_page}&page={page}"
        response = requests.get(url, headers=HEADERS)
        if response.status_code != 200:
            print_warn(f"GitHub API Error {response.status_code}: {response.text}")
            break
        data = response.json()
        items = data.get("items", [])
        if not items:
            break
        results.extend(items)
        if len(items) < per_page:
            break
        page += 1
        sleep(1)
    return results

def get_last_commit(repo_full_name):
    url = f"https://api.github.com/repos/{repo_full_name}/commits?per_page=1"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200 or not response.json():
        return ("Unknown", "Unknown")
    commit_data = response.json()[0]
    commiter = commit_data["commit"]["committer"]["name"]
    date = commit_data["commit"]["committer"]["date"]
    return (commiter, date)

def get_repo_size(repo_full_name):
    url = f"https://api.github.com/repos/{repo_full_name}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        return None, None
    repo_data = response.json()
    return repo_data.get("size", None), repo_data.get("private", None)

# ======== Основной пайплайн ========
total_repos_count = 0
matched_repos_count = 0

results_list = []
public_list = []

for keyword in SEARCH_KEYWORDS:
    if args.issues:
        issues_results = search_github_issues_all_pages(keyword)
        for issue in issues_results:
            issue_url = issue["html_url"]
            issue_title = issue["title"]
            snippet = issue.get("body", "")[:200].replace("\n", " ")
            results_list.append({
                "Github Link": "",
                "Last Commiter": "",
                "Date of Last Commit": "",
                "Detector Type": "",
                "File Path": "",
                "Line Number": "",
                "Raw Result": "",
                "Issue URL": issue_url,
                "Issue Title": issue_title,
                "Issue Body Snippet": snippet
            })
            print_secret("", issue_url=issue_url, issue_title=issue_title, issue_body_snippet=snippet)
            matched_repos_count += 1
    else:
        code_results = search_github_code_all_pages(keyword)
        for item in code_results:
            repo_url = item["repository"]["html_url"]
            repo_full_name = item["repository"]["full_name"]
            total_repos_count += 1

            repo_size_kb, is_private = get_repo_size(repo_full_name)
            if is_private:
                print_warn(f"Skipping repo (private): {repo_url}")
                continue

            local_path = os.path.join(TEMP_DIR, repo_full_name.replace("/", "_"))
            if repo_size_kb and repo_size_kb > MAX_SIZE_KB:
                size_mb = repo_size_kb / 1024
                print_warn(f"Skipping repo (too large {size_mb:.2f} MB > {args.max_size} MB): {repo_url}")
                public_list.append({
                    "Github Link": repo_url,
                    "Author": "",
                    "Date of Last Commit": "",
                    "Keyword": keyword
                })
                continue

            try:
                subprocess.run(["git", "clone", "--quiet", "--depth", "1", repo_url, local_path], check=True)
            except subprocess.CalledProcessError:
                print_warn(f"Failed to clone {repo_url}")
                continue

            commiter, last_commit_date = get_last_commit(repo_full_name)
            public_list.append({
                "Github Link": repo_url,
                "Author": commiter,
                "Date of Last Commit": last_commit_date,
                "Keyword": keyword
            })

            try:
                result = subprocess.run(
                    ["trufflehog", "filesystem", "--only-verified", local_path],
                    capture_output=True,
                    text=True,
                    check=False
                )
                output = result.stdout.splitlines()
                current_detector = ""
                current_file = ""
                current_line = ""

                for line in output:
                    line = line.strip()
                    dt_match = re.search(r"Detector Type:\s*(.*)", line)
                    rr_match = re.search(r"Raw result:\s*(.*)", line)
                    file_match = re.search(r"Path:\s*(.*)", line)
                    line_match = re.search(r"Line Number:\s*(\d+)", line)

                    if dt_match:
                        current_detector = dt_match.group(1).strip()
                    if file_match:
                        current_file = file_match.group(1).strip()
                    if line_match:
                        current_line = line_match.group(1).strip()
                    if rr_match:
                        raw_result = rr_match.group(1).strip()
                        if raw_result:
                            results_list.append({
                                "Github Link": repo_url,
                                "Last Commiter": commiter,
                                "Date of Last Commit": last_commit_date,
                                "Detector Type": current_detector,
                                "File Path": current_file,
                                "Line Number": current_line,
                                "Raw Result": raw_result,
                                "Issue URL": "",
                                "Issue Title": "",
                                "Issue Body Snippet": ""
                            })
                            print_secret(repo_url, current_detector, current_file, current_line, raw_result)
                            matched_repos_count += 1

                print_info(f"SUCCESS scanning repo: {repo_url}")

            except Exception:
                print_warn(f"Error scanning repo {repo_url}")

            shutil.rmtree(local_path, ignore_errors=True)
            sleep(1)

# ======== Сохраняем результаты ========
if args.xlsx:
    df_results = pd.DataFrame(results_list)
    df_results.to_excel(RESULT_FILE, index=False)

    df_public = pd.DataFrame(public_list)
    df_public.to_excel(PUBLIC_REPOS_FILE, index=False)
else:
    with open(RESULT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=[
            "Github Link","Last Commiter","Date of Last Commit","Detector Type",
            "File Path","Line Number","Raw Result","Issue URL","Issue Title","Issue Body Snippet"
        ])
        writer.writeheader()
        writer.writerows(results_list)

    with open(PUBLIC_REPOS_FILE, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["Github Link","Author","Date of Last Commit","Keyword"])
        writer.writeheader()
        writer.writerows(public_list)

# ======== Итоговая статистика ========
print_info(f"Total repositories scanned: {total_repos_count}")
print_info(f"Repositories/issues with matched secrets: {matched_repos_count}")
print_info(f"Scan complete! Secrets saved to {RESULT_FILE}")
print_info(f"Public repo info saved to {PUBLIC_REPOS_FILE}")
