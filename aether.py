#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import re
import time
import hashlib
import difflib
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
import httpx

console = Console()

# Headers crafted to blend in during fuzzing
BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (Professional Security Scanner)",
    "Accept": "text/html,application/json,*/*;q=0.9",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "X-Security-Testing": "Authorized vulnerability assessment"
}

@dataclass
class ClassificationResult:
    category: str
    confidence: float
    details: Dict[str, Any]
    raw_id: str

    def to_dict(self):
    # Prepare data for JSON serialization
        return {
            'category': self.category,
            'confidence': self.confidence,
            'details': self.details,
            'raw_id': self.raw_id
        }

class ProfessionalFuzzer:
    def __init__(self, headers: Optional[Dict] = None):
        self.headers = headers or BASE_HEADERS
        self.baseline = None

    def parse_fuzz_url(self, url: str) -> Dict[str, Any]:
        # Parse URL and detect FUZZ injection vectors
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # Identify FUZZ injection points in path
        path_parts = parsed.path.split('/')
        fuzz_path_indices = [i for i, part in enumerate(path_parts) if 'FUZZ' in part]

        # Detect FUZZ markers in query parameters
        fuzz_params = [k for k, v in query_params.items() if any('FUZZ' in val for val in v)]

        return {
            'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            'path_parts': path_parts,
            'query_params': query_params,
            'fuzz_path_indices': fuzz_path_indices,
            'fuzz_params': fuzz_params,
            'original_url': url
        }

    def build_request_url(self, original_url: str, fuzz_data: Dict, payload: str) -> str:
        # Build request URL by injecting payload into FUZZ positions
        parsed = urlparse(original_url)
        new_path_parts = fuzz_data['path_parts'][:]

        # Inject payload into FUZZ markers in path
        for idx in fuzz_data['fuzz_path_indices']:
            new_path_parts[idx] = new_path_parts[idx].replace('FUZZ', payload)

        new_path = '/'.join(new_path_parts)

        # Replace FUZZ markers in query parameters
        new_query_params = {}
        for key, values in fuzz_data['query_params'].items():
            new_values = [val.replace('FUZZ', payload) for val in values]
            new_query_params[key] = new_values

        new_query = urlencode(new_query_params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{new_path}?{new_query}"

    async def get_baseline(self, client: httpx.AsyncClient, url: str, method: str = "GET") -> Dict[str, Any]:

       # Get baseline response for comparison
        try:
            if method == "GET":
                response = await client.get(url, headers=self.headers)
            else:
                response = await client.post(url, headers=self.headers, json={})

            return {
                'url': url,
                'method': method,
                'status_code': response.status_code,
                'content_length': len(response.text),
                'response_time': response.elapsed.total_seconds(),
                'headers': dict(response.headers),
                'body': response.text,
                'body_hash': hashlib.md5(response.text.encode()).hexdigest()
            }
        except httpx.RequestError as e:
            return {
                'url': url,
                'method': method,
                'status_code': 0,
                'content_length': 0,
                'response_time': 0,
                'headers': {},
                'body': '',
                'body_hash': '',
                'error': str(e)
            }

    def calculate_content_similarity(self, baseline_body: str, current_body: str) -> float:
        #Calculate content similarity using sequence matching
        if not baseline_body and not current_body:
            return 1.0
        if not baseline_body or not current_body:
            return 0.0

        similarity = difflib.SequenceMatcher(None, baseline_body, current_body).ratio()
        return round(similarity, 3)

    def classify_response(self, response: Dict[str, Any], baseline: Dict[str, Any]) -> ClassificationResult:
        # Classify response based on how it differs from the baseline
        if 'error' in baseline:
            return ClassificationResult(
                category='baseline_error',
                confidence=1.0,
                details={'error': baseline['error']},
                raw_id='baseline_error'
            )

        similarity = self.calculate_content_similarity(baseline['body'], response.get('body', ''))

        category = 'normal'
        confidence = 0.9
        details = {}

        # Status code changes
        if response['status_code'] != baseline['status_code']:
            if response['status_code'] == 200 and baseline['status_code'] != 200:
                category = 'unauthorized_access'
                confidence = 0.95
            elif response['status_code'] in [500, 502, 503]:
                category = 'server_error'
                confidence = 0.9
            else:
                category = 'status_change'
                confidence = 0.85

            details = {
                'baseline_status': baseline['status_code'],
                'current_status': response['status_code']
            }
            return ClassificationResult(category, confidence, details, self.generate_raw_id(response))

        # Content length anomalies
        baseline_length = baseline['content_length']
        current_length = response['content_length']
        length_diff = abs(current_length - baseline_length)

        if length_diff > 1000 or (baseline_length > 0 and length_diff / baseline_length > 0.5):
            category = 'content_variation'
            confidence = 0.8
            details = {
                'baseline_length': baseline_length,
                'current_length': current_length,
                'length_difference': length_diff
            }
            return ClassificationResult(category, confidence, details, self.generate_raw_id(response))

        # Identify abnormal response timing
        baseline_time = baseline['response_time']
        current_time = response['response_time']

        if baseline_time > 0 and current_time > baseline_time * 3:
            category = 'timing_anomaly'
            confidence = 0.85
            details = {
                'baseline_time': baseline_time,
                'current_time': current_time,
                'slowdown_factor': round(current_time / baseline_time, 1)
            }
            return ClassificationResult(category, confidence, details, self.generate_raw_id(response))

        # Content similarity analysis
        if similarity < 0.7:
            category = 'content_change'
            confidence = 0.9 - (0.2 * similarity)
            details = {
                'similarity_score': similarity,
                'content_preview': response.get('body', '')[:200]
            }
            return ClassificationResult(category, confidence, details, self.generate_raw_id(response))

        return ClassificationResult(category, confidence, details, self.generate_raw_id(response))

    def generate_raw_id(self, response: Dict[str, Any]) -> str:
        # Generate unique identifier for raw response artifacts
        content = f"{response['url']}{response.get('body', '')}{response['status_code']}{time.time()}"
        return hashlib.md5(content.encode()).hexdigest()[:8]

    async def fuzz_request(self, client: httpx.AsyncClient, url: str, method: str = "GET") -> Dict[str, Any]:
        #Make a single fuzz request
        try:
            if method == "GET":
                response = await client.get(url, headers=self.headers)
            else:
                response = await client.post(url, headers=self.headers, json={})

            return {
                'url': url,
                'method': method,
                'status_code': response.status_code,
                'content_length': len(response.text),
                'response_time': response.elapsed.total_seconds(),
                'headers': dict(response.headers),
                'body': response.text,
                'body_hash': hashlib.md5(response.text.encode()).hexdigest()
            }
        except httpx.RequestError as e:
            return {
                'url': url,
                'method': method,
                'status_code': 0,
                'content_length': 0,
                'response_time': 0,
                'headers': {},
                'body': '',
                'body_hash': '',
                'error': str(e)
            }

class ResultsManager:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.setup_directories()

    def setup_directories(self):
       # Setup output directory structure
        directories = [
            f"{self.output_dir}/baseline",
            f"{self.output_dir}/normal",
            f"{self.output_dir}/anomalies",
            f"{self.output_dir}/payload_effects",
            f"{self.output_dir}/raw"
        ]

        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    async def save_raw_response(self, response: Dict[str, Any], raw_id: str, payload: str):
        # Store raw request and response for forensic analysis
        req_filename = f"{self.output_dir}/raw/{raw_id}.req.txt"
        res_filename = f"{self.output_dir}/raw/{raw_id}.res.txt"

        headers_str = "\n".join([f"{k}: {v}" for k, v in response.get('headers', {}).items()])
        req_content = f"GET {response['url']} HTTP/1.1\n{headers_str}\n\nPayload: {payload}\n"

        with open(req_filename, 'w') as f:
            f.write(req_content)

        res_headers_str = "\n".join([f"{k}: {v}" for k, v in response.get('headers', {}).items()])
        res_content = f"HTTP/1.1 {response['status_code']}\n{res_headers_str}\n\n{response.get('body', '')}"

        with open(res_filename, 'w') as f:
            f.write(res_content)

async def main():
    parser = argparse.ArgumentParser(description="Professional Classification-Driven Attack Engine")
    parser.add_argument("-u", "--url", required=True, help="Target URL with FUZZ placeholder")
    parser.add_argument("-w", "--wordlist", required=True, help="File with payloads")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("-H", "--header", action="append", help="Add custom header (key:value)")
    parser.add_argument("-r", "--rate", type=int, default=10, help="Requests per second")
    parser.add_argument("-o", "--output", default="vortex_results", help="Output directory")

    args = parser.parse_args()

    if 'FUZZ' not in args.url:
        console.print("[red]ERROR: URL must contain 'FUZZ' placeholder[/red]")
        return

    if not os.path.exists(args.wordlist):
        console.print(f"[red]ERROR: Wordlist file not found: {args.wordlist}[/red]")
        return

    with open(args.wordlist) as f:
        payloads = [line.strip() for line in f if line.strip()]

    if not payloads:
        console.print(f"[red]ERROR: No payloads found in {args.wordlist}[/red]")
        return

    headers = BASE_HEADERS.copy()
    if args.header:
        for h in args.header:
            key, value = h.split(':', 1)
            headers[key.strip()] = value.strip()

    fuzzer = ProfessionalFuzzer(headers)
    results_manager = ResultsManager(args.output)

    async with httpx.AsyncClient(timeout=30, verify=False) as client:
        console.print(f"[yellow]Getting baseline for: {args.url}[/yellow]")
        baseline = await fuzzer.get_baseline(client, args.url, args.method)

        if 'error' in baseline:
            console.print(f"[red]Error getting baseline: {baseline['error']}[/red]")
            return

        console.print(f"[green]Baseline obtained: {baseline['status_code']} {baseline['content_length']} bytes[/green]")

    fuzzer.baseline = baseline

    results = {
        'normal': [],
        'anomalies': {
            'status_change': [],
            'content_variation': [],
            'unauthorized_access': [],
            'server_error': [],
            'timing_anomaly': [],
            'content_change': [],
            'baseline_error': []
        },
        'payload_effects': {
            'payload_map': [],
            'payload_clusters': {}
        }
    }

    semaphore = asyncio.Semaphore(args.rate)

    async def classify_payload(payload):
        async with semaphore:
            fuzz_data = fuzzer.parse_fuzz_url(args.url)
            fuzzed_url = fuzzer.build_request_url(args.url, fuzz_data, payload)

            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                response = await fuzzer.fuzz_request(client, fuzzed_url, args.method)

            classification = fuzzer.classify_response(response, baseline)
            await results_manager.save_raw_response(response, classification.raw_id, payload)

            result_entry = {
                'payload': payload,
                'response': response,
                'classification': classification.to_dict()
            }

            if classification.category == 'normal':
                results['normal'].append(result_entry)
            else:
                if classification.category in results['anomalies']:
                    results['anomalies'][classification.category].append(result_entry)
                else:
                    results['anomalies'][classification.category] = [result_entry]

            results['payload_effects']['payload_map'].append({
                'payload': payload,
                'category': classification.category,
                'raw_id': classification.raw_id,
                'status': response['status_code'],
                'length': response['content_length']
            })

            if classification.category not in results['payload_effects']['payload_clusters']:
                results['payload_effects']['payload_clusters'][classification.category] = []
            results['payload_effects']['payload_clusters'][classification.category].append(payload)

            return classification

    tasks = [classify_payload(payload) for payload in payloads]

    with Progress(
        SpinnerColumn(),
        *Progress.get_default_columns(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Classifying...", total=len(payloads))

        for coro in asyncio.as_completed(tasks):
            await coro
            progress.advance(task)

    save_results(results, args.output, baseline)
    show_summary(results, args.output)

def save_results(results: Dict, output_dir: str, baseline: Dict):
    """Save classified results to appropriate directories"""
    with open(f"{output_dir}/baseline/baseline.json", 'w') as f:
        json.dump(baseline, f, indent=2)

    normal_serializable = []
    for item in results['normal']:
        serializable_item = {
            'payload': item['payload'],
            'response': item['response'],
            'classification': item['classification']
        }
        normal_serializable.append(serializable_item)

    with open(f"{output_dir}/normal/normal_responses.json", 'w') as f:
        json.dump(normal_serializable, f, indent=2)

    for category, items in results['anomalies'].items():
        if items:
            serializable_items = []
            for item in items:
                serializable_item = {
                    'payload': item['payload'],
                    'response': item['response'],
                    'classification': item['classification']
                }
                serializable_items.append(serializable_item)

            with open(f"{output_dir}/anomalies/{category}.json", 'w') as f:
                json.dump(serializable_items, f, indent=2)

    with open(f"{output_dir}/payload_effects/payload_map.json", 'w') as f:
        json.dump(results['payload_effects']['payload_map'], f, indent=2)

    with open(f"{output_dir}/payload_effects/payload_clusters.json", 'w') as f:
        json.dump(results['payload_effects']['payload_clusters'], f, indent=2)

    index = {
        'baseline_id': baseline.get('body_hash', 'unknown')[:8],
        'total_payloads': sum([
            len(results['normal']),
            sum(len(v) for v in results['anomalies'].values())
        ]),
        'normal': len(results['normal']),
        'anomalies': {k: len(v) for k, v in results['anomalies'].items() if v}
    }

    with open(f"{output_dir}/index.json", 'w') as f:
        json.dump(index, f, indent=2)

def show_summary(results: Dict, output_dir: str):
    """Show professional summary of results"""
    console.print("\n[green]Classification complete![/green]")
    console.print(f"[white]Results saved to: {output_dir}[/white]")

    table = Table(title="Classification Summary", show_lines=True)
    table.add_column("Category", style="bold")
    table.add_column("Count", style="cyan")

    table.add_row("Normal", str(len(results['normal'])))

    for category, items in results['anomalies'].items():
        if items:
            table.add_row(category.replace('_', ' ').title(), str(len(items)))

    console.print(table)

    console.print("\n[blue]Directory structure created:[/blue]")
    console.print("├── baseline/")
    console.print("├── normal/")
    console.print("├── anomalies/")
    console.print("├── payload_effects/")
    console.print("├── raw/")
    console.print("└── index.json")

if __name__ == "__main__":
    asyncio.run(main())
