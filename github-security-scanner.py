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
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom

# ======== Аргументы командной строки ========
parser = argparse.ArgumentParser(description="GitHub search + TruffleHog scan")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-k", "--keyword", help="Single keyword to search")
group.add_argument("-kf", "--keywords-file", help="File with keywords (one per line)")
parser.add_argument("-t", "--token", help="GitHub API token")
parser.add_argument("-o", "--output", default="github_secrets", help="Output filename without extension (default: github_secrets)")
parser.add_argument("--max-size", type=int, default=500, help="Max repo size in MB (default: 500MB)")
parser.add_argument("--issues", action="store_true", help="Search only in GitHub issues instead of code")

# Форматы вывода (можно указать несколько)
parser.add_argument("--xlsx", action="store_true", help="Save results to Excel (XLSX) format")
parser.add_argument("--csv", action="store_true", help="Save results to CSV format")
parser.add_argument("--json", action="store_true", help="Save results to JSON format")
parser.add_argument("--xml", action="store_true", help="Save results to XML format")
parser.add_argument("--txt", action="store_true", help="Save results to TXT format (pipe-separated)")

args = parser.parse_args()

# ======== Настройки ========
GITHUB_TOKEN = args.token
OUTPUT_BASENAME = args.output
TEMP_DIR = "./temp_repos"
MAX_SIZE_KB = args.max_size * 1024  # KB

# Если не указан ни один формат, по умолчанию используем XLSX
if not any([args.xlsx, args.csv, args.json, args.xml, args.txt]):
    args.xlsx = True

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

def print_secret(repo_url, keyword="", detector_type="", file_path="", line_number="", raw_result="", issue_url="", issue_title="", issue_body_snippet=""):
    if issue_url:
        print(f"[ISSUE] Keyword: {keyword} | URL: {issue_url} | Title: {issue_title} | Snippet: {issue_body_snippet}")
    else:
        print(f"[SECRET] Keyword: {keyword} | Repo: {repo_url} | Detector: {detector_type} | File: {file_path}:{line_number} | Secret: {raw_result}")

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

# ======== Функции сохранения в разных форматах ========
def save_to_xlsx(data, filename):
    """Сохранение в Excel формат"""
    df = pd.DataFrame(data)
    df.to_excel(filename, index=False)
    print_info(f"Results saved to {filename}")

def save_to_csv(data, filename):
    """Сохранение в CSV формат"""
    if not data:
        print_warn(f"No data to save to {filename}")
        return
    
    fieldnames = list(data[0].keys())
    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    print_info(f"Results saved to {filename}")

def save_to_json(data, filename):
    """Сохранение в JSON формат"""
    with open(filename, "w", encoding="utf-8") as jsonfile:
        json.dump(data, jsonfile, indent=2, ensure_ascii=False)
    print_info(f"Results saved to {filename}")

def save_to_xml(data, filename):
    """Сохранение в XML формат"""
    root = ET.Element("results")
    
    for item in data:
        record = ET.SubElement(root, "record")
        for key, value in item.items():
            element = ET.SubElement(record, key.replace(" ", "_").lower())
            element.text = str(value) if value else ""
    
    # Форматирование XML для читабельности
    xml_str = ET.tostring(root, encoding='unicode')
    dom = minidom.parseString(xml_str)
    pretty_xml = dom.toprettyxml(indent="  ")
    
    with open(filename, "w", encoding="utf-8") as xmlfile:
        xmlfile.write(pretty_xml)
    print_info(f"Results saved to {filename}")

def save_to_txt(data, filename):
    """Сохранение в TXT формат (pipe-separated)"""
    if not data:
        print_warn(f"No data to save to {filename}")
        return
    
    with open(filename, "w", encoding="utf-8") as txtfile:
        # Заголовки
        fieldnames = list(data[0].keys())
        txtfile.write(" | ".join(fieldnames) + "\n")
        txtfile.write("-" * (len(" | ".join(fieldnames))) + "\n")
        
        # Данные
        for item in data:
            row = " | ".join(str(item.get(field, "")) for field in fieldnames)
            txtfile.write(row + "\n")
    
    print_info(f"Results saved to {filename}")

def save_results(data, basename, formats):
    """Сохранение результатов во всех указанных форматах"""
    if args.xlsx:
        save_to_xlsx(data, f"{basename}.xlsx")
    if args.csv:
        save_to_csv(data, f"{basename}.csv")
    if args.json:
        save_to_json(data, f"{basename}.json")
    if args.xml:
        save_to_xml(data, f"{basename}.xml")
    if args.txt:
        save_to_txt(data, f"{basename}.txt")

# ======== Основной пайплайн ========
total_repos_count = 0
matched_repos_count = 0

results_list = []
public_list = []

for keyword in SEARCH_KEYWORDS:
    print_info(f"Processing keyword: '{keyword}'")
    
    if args.issues:
        issues_results = search_github_issues_all_pages(keyword)
        for issue in issues_results:
            issue_url = issue["html_url"]
            issue_title = issue["title"]
            snippet = issue.get("body", "")[:200].replace("\n", " ")
            results_list.append({
                "Keyword": keyword,
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
            print_secret("", keyword=keyword, issue_url=issue_url, issue_title=issue_title, issue_body_snippet=snippet)
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
                                "Keyword": keyword,
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
                            print_secret(repo_url, keyword=keyword, detector_type=current_detector, 
                                       file_path=current_file, line_number=current_line, raw_result=raw_result)
                            matched_repos_count += 1

                print_info(f"SUCCESS scanning repo: {repo_url}")

            except Exception as e:
                print_warn(f"Error scanning repo {repo_url}: {e}")

            shutil.rmtree(local_path, ignore_errors=True)
            sleep(1)

# ======== Сохраняем результаты ========
print_info("Saving results...")
save_results(results_list, OUTPUT_BASENAME, args)
save_results(public_list, f"{OUTPUT_BASENAME}_public_repos", args)

# ======== Итоговая статистика ========
print_info(f"Total repositories scanned: {total_repos_count}")
print_info(f"Repositories/issues with matched secrets: {matched_repos_count}")
print_info(f"Scan complete!")
