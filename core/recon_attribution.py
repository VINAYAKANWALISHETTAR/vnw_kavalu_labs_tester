"""
Reconnaissance Attribution Module
Performs real dynamic discovery of:
1. Target deployment infrastructure, hosting platform, server IP, reverse DNS, and geolocation.
2. Target author, developer name, organization, copyright, and developer social footprint.
"""

__author__ = "Kavalu Labs"

import socket
import re
import json
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Optional


class TargetAttribution:
    """Discovers deployment platform and author/developer attribution for a target URL."""

    KNOWN_PLATFORMS = [
        ('Vercel', ['x-vercel-id', 'x-vercel-cache', 'x-vercel-ip-country']),
        ('Netlify', ['x-nf-request-id', 'x-nf-subdomain-type']),
        ('Cloudflare / Cloudflare Pages', ['cf-ray', 'cf-cache-status']),
        ('AWS CloudFront / S3', ['x-amz-cf-id', 'x-amz-request-id', 'x-amz-id-2']),
        ('GitHub Pages', ['x-github-request-id']),
        ('Firebase / Google Cloud', ['x-firebase-hosting']),
        ('Render', ['render-proxy-id']),
        ('Heroku', ['via: vegur']),
        ('Fly.io', ['fly-request-id']),
        ('Fastly', ['x-fastly-request-id']),
        ('Microsoft Azure', ['x-ms-request-id', 'x-ms-routing-request-id'])
    ]

    @classmethod
    def analyze(cls, target_url: str, response: Optional[requests.Response] = None) -> Dict[str, Any]:
        """
        Run complete deployment and developer discovery on the target URL.
        """
        parsed = urlparse(target_url)
        hostname = parsed.hostname or ''
        scheme = parsed.scheme or 'https'

        deployment = cls._discover_deployment(hostname, response)
        developer = cls._discover_developer(target_url, hostname, scheme, response)

        return {
            'deployment': deployment,
            'developer': developer
        }

    @classmethod
    def _discover_deployment(cls, hostname: str, response: Optional[requests.Response]) -> Dict[str, Any]:
        """Discovers deployment platform, IP, reverse DNS, and server location."""
        info = {
            'platform': 'Unknown / Custom Server',
            'ip_address': 'Unknown',
            'reverse_dns': 'N/A',
            'server_header': 'N/A',
            'location': 'Unknown',
            'isp': 'Unknown',
            'hosting_org': 'Unknown',
            'asn': 'N/A',
            'detected_headers': []
        }

        if not hostname:
            return info

        headers = response.headers if response is not None else {}
        server_header = headers.get('Server', '')
        info['server_header'] = server_header or 'Hidden / Not Provided'

        # 1. Platform fingerprinting via HTTP Headers
        detected_platform = None
        for platform_name, signature_headers in cls.KNOWN_PLATFORMS:
            for sig in signature_headers:
                if ':' in sig:
                    header_key, header_val = sig.split(':', 1)
                    if headers.get(header_key.strip(), '').lower() == header_val.strip().lower():
                        detected_platform = platform_name
                        info['detected_headers'].append(f"{header_key}: {headers.get(header_key.strip())}")
                        break
                elif sig in headers:
                    detected_platform = platform_name
                    info['detected_headers'].append(f"{sig}: {headers.get(sig)}")
                    break
            if detected_platform:
                break

        # Fallback to Server header matching
        if not detected_platform and server_header:
            s_lower = server_header.lower()
            if 'vercel' in s_lower:
                detected_platform = 'Vercel'
            elif 'cloudflare' in s_lower:
                detected_platform = 'Cloudflare'
            elif 'netlify' in s_lower:
                detected_platform = 'Netlify'
            elif 'github' in s_lower:
                detected_platform = 'GitHub Pages'
            elif 'amazon' in s_lower or 'awselb' in s_lower:
                detected_platform = 'AWS Infrastructure'
            elif 'google' in s_lower:
                detected_platform = 'Google Cloud / Google Frontend'
            elif 'nginx' in s_lower:
                detected_platform = f"Nginx ({server_header})"
            elif 'apache' in s_lower:
                detected_platform = f"Apache ({server_header})"
            elif 'litespeed' in s_lower:
                detected_platform = 'LiteSpeed Web Server'
            elif 'microsoft-iis' in s_lower:
                detected_platform = 'Microsoft IIS (Windows Server)'
            else:
                detected_platform = f"Custom Server ({server_header})"

        # 2. IP Resolution
        ip_address = None
        try:
            ip_address = socket.gethostbyname(hostname)
            info['ip_address'] = ip_address
        except Exception:
            info['ip_address'] = 'Unable to resolve DNS'

        # 3. Reverse DNS
        if ip_address:
            try:
                host_info = socket.gethostbyaddr(ip_address)
                if host_info and host_info[0]:
                    info['reverse_dns'] = host_info[0]
                    # Check if reverse DNS reveals platform
                    rdns_lower = host_info[0].lower()
                    if not detected_platform or 'Unknown' in detected_platform:
                        if 'vercel-dns' in rdns_lower or 'vercel' in rdns_lower:
                            detected_platform = 'Vercel'
                        elif 'cloudflare' in rdns_lower:
                            detected_platform = 'Cloudflare'
                        elif 'amazonaws' in rdns_lower or 'cloudfront' in rdns_lower:
                            detected_platform = 'AWS Infrastructure'
                        elif 'google' in rdns_lower or '1e100.net' in rdns_lower:
                            detected_platform = 'Google Cloud Infrastructure'
                        elif 'digitalocean' in rdns_lower:
                            detected_platform = 'DigitalOcean'
                        elif 'github.io' in rdns_lower:
                            detected_platform = 'GitHub Pages'
            except Exception:
                info['reverse_dns'] = 'PTR record not configured'

        # 4. Geolocation and Autonomous System (ASN) lookup via public IP API
        if ip_address and ip_address != 'Unable to resolve DNS':
            try:
                geo_resp = requests.get(
                    f"http://ip-api.com/json/{ip_address}?fields=status,country,regionName,city,isp,org,as",
                    timeout=3.0
                )
                if geo_resp.status_code == 200:
                    geo_data = geo_resp.json()
                    if geo_data.get('status') == 'success':
                        city = geo_data.get('city', '')
                        region = geo_data.get('regionName', '')
                        country = geo_data.get('country', '')
                        loc_parts = [p for p in [city, region, country] if p]
                        info['location'] = ', '.join(loc_parts) if loc_parts else 'Unknown'
                        info['isp'] = geo_data.get('isp', 'Unknown')
                        info['hosting_org'] = geo_data.get('org', geo_data.get('isp', 'Unknown'))
                        info['asn'] = geo_data.get('as', 'N/A')

                        # Detect platform from Org / ASN if still unknown
                        org_lower = (info['hosting_org'] + ' ' + info['isp']).lower()
                        if not detected_platform or 'Unknown' in detected_platform:
                            if 'vercel' in org_lower:
                                detected_platform = 'Vercel'
                            elif 'cloudflare' in org_lower:
                                detected_platform = 'Cloudflare'
                            elif 'amazon' in org_lower:
                                detected_platform = 'Amazon Web Services (AWS)'
                            elif 'digitalocean' in org_lower:
                                detected_platform = 'DigitalOcean'
                            elif 'google' in org_lower:
                                detected_platform = 'Google Cloud'
                            elif 'ovh' in org_lower:
                                detected_platform = 'OVHcloud'
                            elif 'hetzner' in org_lower:
                                detected_platform = 'Hetzner'
                            elif 'linode' in org_lower or 'akamai' in org_lower:
                                detected_platform = 'Akamai / Linode'
            except Exception:
                pass

        info['platform'] = detected_platform or 'Custom Web Server / Self-Hosted'
        return info

    @classmethod
    def _discover_developer(cls, target_url: str, hostname: str, scheme: str, response: Optional[requests.Response]) -> Dict[str, Any]:
        """Discovers developer, author, copyright holder, organization, and social profile links."""
        info = {
            'developer_name': 'Not disclosed in public metadata',
            'organization': 'Not disclosed in public metadata',
            'meta_author': None,
            'copyright': None,
            'social_footprint': [],
            'humans_txt_data': None,
            'confidence': 'Low',
            'discovery_source': 'None'
        }

        if response is None:
            return info

        html_text = ''
        try:
            html_text = response.text
        except Exception:
            return info

        soup = BeautifulSoup(html_text, 'html.parser')

        # 1. Meta Tags Extraction
        meta_author = soup.find('meta', attrs={'name': re.compile(r'^(author|creator|developer|publisher)$', re.I)})
        if meta_author and meta_author.get('content'):
            val = meta_author['content'].strip()
            if val and len(val) < 80:
                info['meta_author'] = val
                info['developer_name'] = val
                info['confidence'] = 'High'
                info['discovery_source'] = f"<meta name=\"{meta_author.get('name', 'author')}\">"

        # Article author or OpenGraph creator
        if info['developer_name'] == 'Not disclosed in public metadata':
            og_author = soup.find('meta', attrs={'property': re.compile(r'^(article:author|og:author)$', re.I)})
            if og_author and og_author.get('content'):
                val = og_author['content'].strip()
                if val and len(val) < 80:
                    info['developer_name'] = val
                    info['confidence'] = 'High'
                    info['discovery_source'] = 'OpenGraph Author Metadata'

        # Site Name / Organization
        og_site = soup.find('meta', attrs={'property': 'og:site_name'})
        if og_site and og_site.get('content'):
            val = og_site['content'].strip()
            if val and len(val) < 100:
                info['organization'] = val

        # Meta copyright
        meta_copyright = soup.find('meta', attrs={'name': re.compile(r'^copyright$', re.I)})
        if meta_copyright and meta_copyright.get('content'):
            info['copyright'] = meta_copyright['content'].strip()
            if info['developer_name'] == 'Not disclosed in public metadata':
                info['developer_name'] = meta_copyright['content'].strip()
                info['confidence'] = 'Medium'
                info['discovery_source'] = '<meta name="copyright">'

        # 2. JSON-LD / Schema.org Structured Data
        for script in soup.find_all('script', type='application/ld+json'):
            try:
                data = json.loads(script.string or '')
                candidates = data if isinstance(data, list) else [data]
                for item in candidates:
                    if not isinstance(item, dict):
                        continue
                    # Check author, creator, publisher
                    for role in ['author', 'creator', 'publisher', 'copyrightHolder']:
                        entity = item.get(role)
                        if isinstance(entity, dict) and entity.get('name'):
                            ent_name = str(entity['name']).strip()
                            if ent_name and info['developer_name'] == 'Not disclosed in public metadata':
                                info['developer_name'] = ent_name
                                info['confidence'] = 'High'
                                info['discovery_source'] = f"Schema.org JSON-LD ({role})"
                        elif isinstance(entity, str) and entity.strip():
                            if info['developer_name'] == 'Not disclosed in public metadata':
                                info['developer_name'] = entity.strip()
                                info['confidence'] = 'High'
                                info['discovery_source'] = f"Schema.org JSON-LD ({role})"
                    # Organization check
                    if item.get('@type') in ['Organization', 'Corporation'] and item.get('name'):
                        info['organization'] = str(item['name']).strip()
            except Exception:
                pass

        # 3. Probe humans.txt convention
        try:
            humans_url = f"{scheme}://{hostname}/humans.txt"
            h_resp = requests.get(humans_url, timeout=2.5, verify=False)
            if h_resp.status_code == 200 and h_resp.text and len(h_resp.text) < 5000:
                h_text = h_resp.text.strip()
                info['humans_txt_data'] = h_text[:300]
                # Look for Author: or Developer: in humans.txt
                h_match = re.search(r'(?:author|developer|creator|designer)\s*:\s*([^\r\n]+)', h_text, re.I)
                if h_match and info['developer_name'] == 'Not disclosed in public metadata':
                    extracted = h_match.group(1).strip()
                    if extracted and len(extracted) < 60:
                        info['developer_name'] = extracted
                        info['confidence'] = 'High'
                        info['discovery_source'] = 'humans.txt'
        except Exception:
            pass

        # 4. Text & Footer Heuristic Regex
        # Only if not already discovered via structured metadata
        footer_tags = soup.find_all(['footer', 'div', 'p', 'span', 'small'])
        for el in footer_tags:
            text = el.get_text(separator=' ', strip=True)
            if not text or len(text) > 200:
                continue

            # Check Developer attribution pattern: "Developed by X", "Built by X", "Designed by X"
            if info['developer_name'] == 'Not disclosed in public metadata':
                dev_match = re.search(
                    r'(?:developed|built|created|designed|coded|maintained)\s+by\s+([A-Za-z0-9\s\.\-]{2,40})', 
                    text, 
                    re.I
                )
                if dev_match:
                    candidate = dev_match.group(1).strip().strip('.').strip(',')
                    # Filter out noise like "WordPress", "Webflow" unless it's a real person/studio
                    if candidate and not re.search(r'^(wordpress|wix|squarespace|shopify|webflow)$', candidate, re.I):
                        info['developer_name'] = candidate
                        info['confidence'] = 'Medium'
                        info['discovery_source'] = 'Page Content ("Developed by" pattern)'

            # Check Copyright pattern
            if not info['copyright']:
                cpy_match = re.search(
                    r'(?:©|&copy;|copyright)\s*(?:\d{4}(?:\s*-\s*\d{4})?)?\s*([A-Za-z0-9\s,\.\-]{2,40})', 
                    text, 
                    re.I
                )
                if cpy_match:
                    info['copyright'] = cpy_match.group(0).strip()
                    if info['organization'] == 'Not disclosed in public metadata':
                        org_cand = cpy_match.group(1).strip().strip('.').strip(',')
                        if org_cand and not re.search(r'^(all rights reserved)$', org_cand, re.I):
                            info['organization'] = org_cand

        # 5. Extract Developer Social Profiles (GitHub, Twitter/X, LinkedIn)
        seen_socials = set()
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            # GitHub profile or repo
            gh_match = re.search(r'https?://(?:www\.)?github\.com/([a-zA-Z0-9_\-]+)(?:/([a-zA-Z0-9_\-]+))?', href)
            if gh_match:
                username = gh_match.group(1)
                if username.lower() not in ['features', 'pricing', 'about', 'blog', 'site', 'security', 'enterprise']:
                    social_str = f"GitHub: @{username}"
                    if social_str not in seen_socials:
                        seen_socials.add(social_str)
                        info['social_footprint'].append({'platform': 'GitHub', 'handle': username, 'url': href})

            # Twitter / X handle
            tw_match = re.search(r'https?://(?:www\.)?(?:twitter|x)\.com/([a-zA-Z0-9_]{1,15})', href)
            if tw_match:
                handle = tw_match.group(1)
                if handle.lower() not in ['home', 'intent', 'share', 'privacy', 'tos']:
                    social_str = f"X/Twitter: @{handle}"
                    if social_str not in seen_socials:
                        seen_socials.add(social_str)
                        info['social_footprint'].append({'platform': 'X/Twitter', 'handle': handle, 'url': href})

            # LinkedIn profile
            li_match = re.search(r'https?://(?:www\.)?linkedin\.com/in/([a-zA-Z0-9_\-]+)', href)
            if li_match:
                li_user = li_match.group(1)
                social_str = f"LinkedIn: {li_user}"
                if social_str not in seen_socials:
                    seen_socials.add(social_str)
                    info['social_footprint'].append({'platform': 'LinkedIn', 'handle': li_user, 'url': href})

        # Fallback organization to title or domain brand if nothing else found
        if info['organization'] == 'Not disclosed in public metadata':
            title_tag = soup.find('title')
            if title_tag and title_tag.string:
                title_str = title_tag.string.strip()
                # If title contains separator like " | " or " - "
                parts = re.split(r'\s*[|\-—–•]\s*', title_str)
                if len(parts) > 1 and parts[-1].strip():
                    info['organization'] = parts[-1].strip()

        return info

