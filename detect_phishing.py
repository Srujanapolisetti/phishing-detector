#!/usr/bin/env python3
"""Simple Phishing URL detector using rule-based heuristics."""
import argparse
import csv
import re
from urllib.parse import urlparse
import difflib

POPULAR_BRANDS = [
    "google","facebook","paypal","amazon","microsoft","linkedin","github","instagram","twitter","apple","youtube","bank"
]

SUSPICIOUS_KEYWORDS = ["login","verify","secure","account","update","bank","webscr","signin","confirm","confirm"]

IP_REGEX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

def extract_domain(netloc):
    # remove port if present
    host = netloc.split(':')[0].lower()
    return host

def is_ip(host):
    return bool(IP_REGEX.match(host))

def count_hyphens(host):
    return host.count('-')

def has_at_symbol(url):
    return '@' in url

def long_url(url):
    return len(url) > 75

def suspicious_keywords_present(path_query):
    path_query = path_query.lower()
    return any(k in path_query for k in SUSPICIOUS_KEYWORDS)

def likely_misspelled_brand(host):
    # extract second-level name (strip subdomains and tld)
    parts = host.split('.')
    # handle case like example.co.uk -> take second last as base if length>2
    if len(parts) >= 2:
        base = parts[-2]
    else:
        base = parts[0]
    # compare to popular brands
    matches = difflib.get_close_matches(base, POPULAR_BRANDS, n=1, cutoff=0.8)
    if matches and matches[0] != base:
        return matches[0], base
    return None, base

def score_url(url):
    # returns score in [0,1] and list of reasons
    reasons = []
    try:
        p = urlparse(url if '://' in url else 'http://' + url)
    except Exception as e:
        return 1.0, ['parse_error']

    host = extract_domain(p.netloc)
    pathq = (p.path or '') + ('?' + p.query if p.query else '')
    score = 0.0

    # IP-based URL
    if is_ip(host):
        score += 0.35
        reasons.append('ip_in_host')

    # many hyphens
    hyphens = count_hyphens(host)
    if hyphens >= 3:
        score += 0.2
        reasons.append(f'many_hyphens({hyphens})')
    elif hyphens >= 1:
        score += 0.05

    # @ symbol (credentials in URL)
    if has_at_symbol(url):
        score += 0.25
        reasons.append('@_in_url')

    # long URL
    if long_url(url):
        score += 0.05
        reasons.append('long_url')

    # suspicious keywords
    if suspicious_keywords_present(pathq):
        score += 0.15
        reasons.append('suspicious_keyword')

    # misspelled brand
    matched_brand, base = likely_misspelled_brand(host)
    if matched_brand:
        score += 0.25
        reasons.append(f'misspelled_brand_like({matched_brand})')
    else:
        # if base equals a popular brand exactly, reduce suspicion (legit)
        if base in POPULAR_BRANDS:
            score -= 0.05

    # HTTP (no TLS) - informational negative weight
    if p.scheme == 'http':
        score += 0.02
        reasons.append('no_https')

    # clamp score 0..1
    if score < 0:
        score = 0.0
    if score > 1:
        score = 1.0

    return round(score, 3), reasons

def label_from_score(score, threshold=0.5):
    return 'phishing' if score >= threshold else 'benign'

def analyze_file(input_path, output_path):
    rows = []
    total = {'phishing':0,'benign':0}
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith('#')]
    for url in lines:
        score, reasons = score_url(url)
        label = label_from_score(score)
        total[label] += 1
        rows.append({'url':url,'score':score,'label':label,'reason':'|'.join(reasons)})

    # write CSV
    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['url','score','label','reason']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    # print summary
    print(f"Analyzed {len(rows)} URLs -> phishing: {total['phishing']}, benign: {total['benign']}")
    print(f"Results written to: {output_path}")

def main():
    ap = argparse.ArgumentParser(description='Simple Phishing URL Detector')
    ap.add_argument('--input', '-i', required=True, help='Input file with one URL per line')
    ap.add_argument('--output', '-o', default='results.csv', help='Output CSV path')
    args = ap.parse_args()
    analyze_file(args.input, args.output)

if __name__ == '__main__':
    main()
