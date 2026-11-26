---
name: safe-fetcher
description: Use when writing any code that fetches external URLs, domains, APKs, or documents.
---
Use the shared fetcher in backend/app/core/fetch.py only. It must: set timeouts, retry with tenacity, rate limit per host, block private/loopback/link-local/metadata IPs, re-validate after every redirect, cap response size, and never write fetched files outside the evidence bucket. Run Playwright only in the sandboxed worker. Never execute downloaded files.
