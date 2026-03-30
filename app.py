#!/usr/bin/env python3
"""
PhishLens - Local Phishing Email Analyzer
A self-hosted PhishTool-style email analysis platform.
"""

import os
import re
import email
import email.policy
import hashlib
import quopri
import base64
from email import header as email_header
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25MB max
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'eml', 'msg', 'txt'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def decode_header_value(raw):
    """Decode RFC 2047 encoded header values."""
    if raw is None:
        return None
    decoded_parts = email_header.decode_header(raw)
    result = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            result.append(part.decode(charset or 'utf-8', errors='replace'))
        else:
            result.append(part)
    return ''.join(result)


def extract_authentication_results(msg):
    """Parse SPF, DKIM, DMARC from Authentication-Results headers."""
    auth = {
        'spf': {'status': 'NONE', 'details': {}},
        'dkim': {'status': 'NONE', 'details': {}},
        'dmarc': {'status': 'NONE', 'details': {}}
    }

    # Check Authentication-Results header
    auth_results = msg.get('Authentication-Results', '')
    if not auth_results:
        auth_results = ''

    # Also check ARC-Authentication-Results
    arc_auth = msg.get('ARC-Authentication-Results', '')

    combined = auth_results + ' ' + (arc_auth or '')

    # SPF
    spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', combined, re.I)
    if spf_match:
        auth['spf']['status'] = spf_match.group(1).upper()

    # Also check Received-SPF header
    received_spf = msg.get('Received-SPF', '')
    if received_spf:
        spf_status_match = re.match(r'(Pass|Fail|SoftFail|Neutral|None|TempError|PermError)', received_spf, re.I)
        if spf_status_match:
            auth['spf']['status'] = spf_status_match.group(1).upper()
        # Extract sender IP
        ip_match = re.search(r'client-ip=([^\s;]+)', received_spf)
        if ip_match:
            auth['spf']['details']['sender_ip'] = ip_match.group(1)
        # Extract domain
        domain_match = re.search(r'domain of (\S+)', received_spf)
        if domain_match:
            auth['spf']['details']['domain'] = domain_match.group(1)

    # SPF record from header details
    spf_ip_match = re.search(r'sender (?:ip |IP is )([^\s\)]+)', combined)
    if spf_ip_match and 'sender_ip' not in auth['spf']['details']:
        auth['spf']['details']['sender_ip'] = spf_ip_match.group(1)

    # DKIM
    dkim_match = re.search(r'dkim=(pass|fail|neutral|none|temperror|permerror)', combined, re.I)
    if dkim_match:
        auth['dkim']['status'] = dkim_match.group(1).upper()

    dkim_sig = msg.get('DKIM-Signature', '')
    if dkim_sig:
        d_match = re.search(r'd=([^\s;]+)', dkim_sig)
        s_match = re.search(r's=([^\s;]+)', dkim_sig)
        a_match = re.search(r'a=([^\s;]+)', dkim_sig)
        if d_match:
            auth['dkim']['details']['signing_domain'] = d_match.group(1)
        if s_match:
            auth['dkim']['details']['selector'] = s_match.group(1)
        if a_match:
            auth['dkim']['details']['algorithm'] = a_match.group(1)

    # Check original auth results for pre-transit DKIM
    orig_auth = msg.get('Authentication-Results-Original', '')
    if orig_auth:
        auth['dkim']['details']['original_result'] = orig_auth.strip()
        # If original shows dkim=none, the sender's domain had no DKIM
        orig_dkim = re.search(r'dkim=(none|fail|neutral)', orig_auth, re.I)
        if orig_dkim:
            auth['dkim']['details']['original_dkim_status'] = orig_dkim.group(1).upper()
            # Override to NEUTRAL if main says pass but original says none
            if auth['dkim']['status'] == 'PASS' and orig_dkim.group(1).upper() == 'NONE':
                auth['dkim']['status'] = 'NEUTRAL'
                auth['dkim']['details']['note'] = 'DKIM signature was added by the mail relay, not the sender\'s domain. Original authentication showed dkim=none.'

    # DMARC
    dmarc_match = re.search(r'dmarc=(pass|fail|bestguesspass|none|temperror|permerror)', combined, re.I)
    if dmarc_match:
        status = dmarc_match.group(1).upper()
        auth['dmarc']['status'] = status

    dmarc_action = re.search(r'dmarc=\S+\s+action=(\S+)', combined, re.I)
    if dmarc_action:
        auth['dmarc']['details']['action'] = dmarc_action.group(1)

    # compauth (composite authentication)
    compauth_match = re.search(r'compauth=(pass|fail|softpass|none)\s+reason=(\d+)', combined, re.I)
    if compauth_match:
        auth['dmarc']['details']['compauth'] = compauth_match.group(1)
        auth['dmarc']['details']['compauth_reason'] = compauth_match.group(2)

    return auth


def parse_received_hops(msg):
    """Parse Received headers into structured hop data."""
    hops = []
    received_headers = msg.get_all('Received', [])

    for i, hdr in enumerate(received_headers):
        hop = {'raw': hdr.strip(), 'hop_number': len(received_headers) - i}

        # Parse "from" server
        from_match = re.search(r'from\s+(\S+)', hdr)
        if from_match:
            hop['from_server'] = from_match.group(1)

        # Parse "from" IP
        from_ip = re.search(r'from\s+\S+\s*\(([^)]+)\)', hdr)
        if from_ip:
            hop['from_ip'] = from_ip.group(1)

        # Parse "by" server
        by_match = re.search(r'by\s+(\S+)', hdr)
        if by_match:
            hop['by_server'] = by_match.group(1)

        # Parse "by" IP
        by_ip = re.search(r'by\s+\S+\s*\(([^)]+)\)', hdr)
        if by_ip:
            hop['by_ip'] = by_ip.group(1)

        # Parse "with" protocol
        with_match = re.search(r'with\s+([\w\s]+?)(?:;|id)', hdr)
        if with_match:
            hop['protocol'] = with_match.group(1).strip()

        # Parse timestamp
        date_match = re.search(r';\s*(.+)$', hdr)
        if date_match:
            date_str = date_match.group(1).strip()
            hop['timestamp_raw'] = date_str
            try:
                dt = parsedate_to_datetime(date_str)
                hop['timestamp'] = dt.isoformat()
                hop['timestamp_utc'] = dt.astimezone(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S UTC')
            except Exception:
                hop['timestamp'] = date_str

        hops.append(hop)

    # Sort by hop number (chronological)
    hops.sort(key=lambda h: h.get('hop_number', 0))

    # Calculate delays between hops
    for i in range(1, len(hops)):
        try:
            prev_dt = parsedate_to_datetime(hops[i-1].get('timestamp_raw', ''))
            curr_dt = parsedate_to_datetime(hops[i].get('timestamp_raw', ''))
            delay = (curr_dt - prev_dt).total_seconds()
            hops[i]['delay_seconds'] = delay
        except Exception:
            hops[i]['delay_seconds'] = None

    return hops


def extract_urls(text):
    """Extract URLs from text content."""
    url_pattern = re.compile(
        r'https?://[^\s<>"\'`\)\]\}]+',
        re.IGNORECASE
    )
    urls = list(set(url_pattern.findall(text or '')))
    return sorted(urls)


def extract_urls_from_html(html_content):
    """Extract URLs from href and src attributes in HTML."""
    urls = set()
    href_pattern = re.compile(r'(?:href|src)=["\']?(https?://[^\s"\'<>]+)', re.I)
    matches = href_pattern.findall(html_content or '')
    urls.update(matches)
    return sorted(urls)


def get_body_content(msg, raw_bytes=None):
    """Extract body content in various formats."""
    body = {
        'plaintext': '',
        'html': '',
        'html_raw': '',
        'source': ''
    }

    def _decode_part(part):
        """Try multiple methods to extract text from a message part."""
        def _try_decode(payload_bytes, declared_charset):
            """Try to decode bytes with declared charset, falling back to common ones."""
            charsets_to_try = []
            if declared_charset:
                charsets_to_try.append(declared_charset)
            charsets_to_try.extend(['utf-8', 'latin-1', 'windows-1252', 'iso-8859-1', 'cp1252', 'ascii'])
            
            for cs in charsets_to_try:
                try:
                    return payload_bytes.decode(cs, errors='replace')
                except (LookupError, UnicodeDecodeError):
                    continue
            # Absolute fallback
            return payload_bytes.decode('utf-8', errors='replace')

        # Method 1: get_payload(decode=True) - handles base64/QP decoding
        try:
            payload = part.get_payload(decode=True)
            if payload and isinstance(payload, bytes):
                charset = part.get_content_charset() or 'utf-8'
                return _try_decode(payload, charset)
        except Exception:
            pass

        # Method 2: get_content() - new-style API (policy.default)
        try:
            content = part.get_content()
            if content and isinstance(content, str):
                return content
        except Exception:
            pass

        # Method 3: get_payload() without decode, then manually decode base64
        try:
            raw = part.get_payload()
            if isinstance(raw, str) and raw.strip():
                import base64
                try:
                    decoded = base64.b64decode(raw)
                    charset = part.get_content_charset() or 'utf-8'
                    return _try_decode(decoded, charset)
                except Exception:
                    return raw
        except Exception:
            pass

        return None

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition', ''))

            if 'attachment' in content_disposition:
                continue

            text = _decode_part(part)
            if not text:
                continue

            if content_type == 'text/plain' and not body['plaintext']:
                body['plaintext'] = text
            elif content_type == 'text/html' and not body['html']:
                body['html'] = text
                body['html_raw'] = text
    else:
        text = _decode_part(msg)
        if text:
            content_type = msg.get_content_type()
            if content_type == 'text/html':
                body['html'] = text
                body['html_raw'] = text
            else:
                body['plaintext'] = text

    # Generate plaintext from HTML if no text/plain part
    if not body['plaintext'] and body['html']:
        import re as _re
        text = body['html']
        text = _re.sub(r'<style[^>]*>.*?</style>', '', text, flags=_re.DOTALL | _re.I)
        text = _re.sub(r'<script[^>]*>.*?</script>', '', text, flags=_re.DOTALL | _re.I)
        text = _re.sub(r'<br\s*/?>', '\n', text, flags=_re.I)
        text = _re.sub(r'</p>', '\n', text, flags=_re.I)
        text = _re.sub(r'</div>', '\n', text, flags=_re.I)
        text = _re.sub(r'</li>', '\n', text, flags=_re.I)
        text = _re.sub(r'<[^>]+>', '', text)
        text = _re.sub(r'&nbsp;', ' ', text)
        text = _re.sub(r'&amp;', '&', text)
        text = _re.sub(r'&lt;', '<', text)
        text = _re.sub(r'&gt;', '>', text)
        text = _re.sub(r'\n{3,}', '\n\n', text)
        body['plaintext'] = text.strip()

    # Source is the raw email - use raw bytes if available, otherwise try as_string
    if raw_bytes:
        body['source'] = raw_bytes.decode('utf-8', errors='replace')
    else:
        try:
            body['source'] = msg.as_string()
        except Exception:
            body['source'] = '[Source view unavailable due to non-standard encoding in email]'

    return body


def detect_true_file_type(payload):
    """Detect actual file type from magic bytes/file signature."""
    if not payload or len(payload) < 4:
        return None

    # Magic byte signatures - ordered by specificity
    signatures = [
        # Executables
        (b'MZ', 'EXE/DLL (PE Executable)'),
        (b'\x7fELF', 'ELF (Linux Executable)'),

        # Archives
        (b'PK\x03\x04', None),  # ZIP-based - needs further inspection
        (b'PK\x05\x06', 'ZIP (Empty Archive)'),
        (b'\x1f\x8b', 'GZIP'),
        (b'Rar!\x1a\x07', 'RAR'),
        (b'7z\xbc\xaf\x27\x1c', '7Z'),

        # Documents
        (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'OLE2 (Legacy Office: DOC/XLS/PPT)'),
        (b'%PDF', 'PDF'),
        (b'{\\rtf', 'RTF'),

        # Images
        (b'\x89PNG\r\n\x1a\n', 'PNG'),
        (b'\xff\xd8\xff', 'JPEG'),
        (b'GIF87a', 'GIF'),
        (b'GIF89a', 'GIF'),
        (b'BM', 'BMP'),
        (b'RIFF', None),  # Could be WEBP, AVI, WAV

        # Scripts/text
        (b'#!/', 'Script (Shell/Python/Perl)'),

        # ISO
        (b'\x00\x00\x00\x00\x00\x00\x00\x00CD001', 'ISO Disk Image'),
    ]

    header = payload[:32]

    for sig, ftype in signatures:
        if header.startswith(sig):
            if ftype is not None:
                return ftype

            # ZIP-based formats need further inspection
            if sig == b'PK\x03\x04':
                # Check internal filenames to determine actual type
                payload_str = payload[:4000]  # Check first 4KB
                if b'word/' in payload_str or b'word\\' in payload_str:
                    if b'vbaProject' in payload:
                        return 'DOCM (Word Document with Macros)'
                    return 'DOCX (Word Document)'
                elif b'xl/' in payload_str or b'xl\\' in payload_str:
                    if b'vbaProject' in payload:
                        return 'XLSM (Excel Spreadsheet with Macros)'
                    return 'XLSX (Excel Spreadsheet)'
                elif b'ppt/' in payload_str or b'ppt\\' in payload_str:
                    if b'vbaProject' in payload:
                        return 'PPTM (PowerPoint with Macros)'
                    return 'PPTX (PowerPoint Presentation)'
                elif b'META-INF/' in payload_str:
                    return 'JAR (Java Archive)'
                elif b'AndroidManifest' in payload_str:
                    return 'APK (Android Package)'
                else:
                    return 'ZIP Archive'

            # RIFF-based formats
            if sig == b'RIFF' and len(header) >= 12:
                riff_type = header[8:12]
                if riff_type == b'WEBP':
                    return 'WEBP'
                elif riff_type == b'AVI ':
                    return 'AVI'
                elif riff_type == b'WAVE':
                    return 'WAV'
                return 'RIFF'

    # Check for HTML/XML/script content (text-based)
    try:
        text_start = payload[:500].decode('utf-8', errors='ignore').strip().lower()
        if text_start.startswith('<!doctype html') or text_start.startswith('<html'):
            return 'HTML'
        elif text_start.startswith('<?xml'):
            return 'XML'
        elif text_start.startswith('<svg'):
            return 'SVG'
        # Catch HTML that starts with other tags (common in phishing)
        elif text_start.startswith(('<table', '<div', '<p ', '<p>', '<body', '<head', '<meta', '<span', '<form', '<img')):
            return 'HTML'
    except Exception:
        pass

    return None


def extract_attachments(msg):
    """Extract attachment metadata including hashes."""
    attachments = []

    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        content_disposition = str(part.get('Content-Disposition', ''))
        if 'attachment' not in content_disposition and 'inline' not in content_disposition:
            # Also check if it has a filename
            filename = part.get_filename()
            if not filename:
                continue

        filename = part.get_filename()
        if not filename:
            continue

        filename = decode_header_value(filename) or filename

        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
        except Exception:
            continue

        size = len(payload)
        md5 = hashlib.md5(payload).hexdigest()
        sha1 = hashlib.sha1(payload).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()

        # Determine file type from extension
        ext = os.path.splitext(filename)[1].lower().lstrip('.')
        content_type = part.get_content_type()
        declared_type = ext.upper() if ext else content_type.split('/')[-1].upper()

        # Detect true file type from magic bytes
        true_type = detect_true_file_type(payload)

        # Check for type mismatch (potential spoofing)
        type_mismatch = False
        if true_type:
            # Normalize for comparison
            true_lower = true_type.lower()
            ext_lower = ext.lower()
            # Check if the declared extension is inconsistent with the actual content
            if ext_lower == 'pdf' and 'pdf' not in true_lower:
                type_mismatch = True
            elif ext_lower in ('doc', 'docx') and 'word' not in true_lower and 'ole2' not in true_lower and 'rtf' not in true_lower:
                type_mismatch = True
            elif ext_lower in ('xls', 'xlsx') and 'excel' not in true_lower and 'ole2' not in true_lower:
                type_mismatch = True
            elif ext_lower in ('jpg', 'jpeg') and 'jpeg' not in true_lower:
                type_mismatch = True
            elif ext_lower == 'png' and 'png' not in true_lower:
                type_mismatch = True
            elif ext_lower == 'zip' and 'zip' not in true_lower:
                type_mismatch = True
            elif ext_lower == 'exe' and 'exe' not in true_lower and 'pe ' not in true_lower:
                type_mismatch = True
            elif ext_lower in ('htm', 'html') and 'html' not in true_lower:
                type_mismatch = True

        # Check for OLE/macro indicators
        ole_indicators = []
        if b'\xd0\xcf\x11\xe0' in payload[:8]:
            ole_indicators.append('OLE2 Compound Document')
        if b'VBA' in payload or b'vbaProject' in payload:
            ole_indicators.append('Macro')
        if b'Auto_Open' in payload or b'AutoOpen' in payload:
            ole_indicators.append('Auto-Execute Macro')
        if b'Document_Open' in payload or b'AutoExec' in payload:
            ole_indicators.append('Auto-Execute Macro')

        attachment = {
            'filename': filename,
            'size': size,
            'size_formatted': format_size(size),
            'content_type': content_type,
            'file_type': declared_type,
            'true_type': true_type,
            'type_mismatch': type_mismatch,
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'ole_indicators': ole_indicators
        }
        attachments.append(attachment)

    return attachments


def format_size(size_bytes):
    """Format bytes into human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def extract_xheaders(msg):
    """Extract X-headers and other non-standard headers."""
    xheaders = []
    standard_headers = {
        'received', 'from', 'to', 'cc', 'bcc', 'subject', 'date',
        'message-id', 'mime-version', 'content-type',
        'content-transfer-encoding', 'return-path', 'reply-to',
        'in-reply-to', 'references', 'sender', 'importance',
        'authentication-results', 'received-spf', 'dkim-signature',
        'arc-seal', 'arc-message-signature', 'arc-authentication-results',
        'authentication-results-original', 'content-disposition'
    }

    seen = set()
    for key in msg.keys():
        lower_key = key.lower()
        if lower_key not in standard_headers and lower_key not in seen:
            seen.add(lower_key)
            value = decode_header_value(msg.get(key, ''))
            xheaders.append({'name': key, 'value': value})

    return xheaders


def detect_flags(analysis):
    """Detect suspicious indicators and flag them."""
    flags = []

    # Check auth failures
    spf_status = analysis['authentication']['spf']['status']
    dkim_status = analysis['authentication']['dkim']['status']
    dmarc_status = analysis['authentication']['dmarc']['status']

    if spf_status in ('FAIL', 'SOFTFAIL', 'NONE'):
        flags.append({'severity': 'high', 'tab': 'authentication', 'message': f'SPF {spf_status}'})
    if dkim_status in ('FAIL', 'NONE'):
        flags.append({'severity': 'high', 'tab': 'authentication', 'message': f'DKIM {dkim_status}'})
    elif dkim_status == 'NEUTRAL':
        flags.append({'severity': 'medium', 'tab': 'authentication', 'message': f'DKIM {dkim_status}'})
    if dmarc_status in ('FAIL', 'NONE'):
        flags.append({'severity': 'high', 'tab': 'authentication', 'message': f'DMARC {dmarc_status}'})
    elif dmarc_status == 'BESTGUESSPASS':
        flags.append({'severity': 'medium', 'tab': 'authentication', 'message': 'DMARC BESTGUESSPASS (no record found)'})

    # Check display name vs from address inconsistency
    display_name = analysis['details'].get('display_name', '')
    from_addr = analysis['details'].get('from_address', '')
    if display_name and from_addr:
        local_part = from_addr.split('@')[0] if '@' in from_addr else from_addr
        dn_lower = display_name.lower()
        local_lower = local_part.lower()
        # If display name looks nothing like the local part, flag it
        if local_lower not in dn_lower and dn_lower.replace(' ', '') not in local_lower:
            analysis['details']['from_context'] = {
                'status': 'warning',
                'title': 'Inconsistent display-name',
                'detail': f"The 'From' email address local-part {local_part} is inconsistent with the display name {display_name} provided in the email.",
                'context': "The use of a misleading display-name is a common, unsophisticated technique used by attackers to fool a target into believing an email has been sent from some other legitimate person or organisation. The use of this technique is driven by email clients displaying the display-name prominently, while displaying the 'From' email address in a less prominent manner."
            }

    # Check From vs Return-Path mismatch
    return_path = analysis['details'].get('return_path', '')
    if from_addr and return_path:
        from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ''
        rp_domain = return_path.split('@')[-1].lower() if '@' in return_path else ''
        if from_domain and rp_domain and from_domain != rp_domain:
            flags.append({'severity': 'medium', 'tab': 'details', 'message': f'From domain ({from_domain}) differs from Return-Path domain ({rp_domain})'})
            analysis['details']['return_path_context'] = {
                'status': 'warning',
                'title': 'Inconsistent Return-Path domain',
                'detail': f"The 'Return-Path' domain {rp_domain} is inconsistent with the 'From' domain {from_domain}. This could indicate a spoofed 'From' address or a legitimate third-party email service.",
                'context': "An SPF check compares the sending SMTP server IP address with the IP address(es) published in the SPF record in the 'Return-Path' domain's DNS resource records. An attacker might insert a 'Return-Path' email address with a domain that they control to successfully PASS an SPF check, whilst also spoofing the 'From' email address."
            }
        else:
            analysis['details']['return_path_context'] = {
                'status': 'success',
                'title': 'Consistent Return-Path domain',
                'detail': f"The 'Return-Path' domain {rp_domain} is consistent with the 'From' domain {from_domain}. The 'Return-Path' will not cause a misleading SPF result.",
                'context': "An SPF check compares the sending SMTP server IP address with the IP address(es) published in the SPF record in the 'Return-Path' domain's DNS resource records. As a result, an attacker might insert a malicious 'Return-Path' email address with a domain that they control to successfully PASS an SPF check, whilst also spoofing the 'From' email address."
            }

    # Check Reply-To mismatch
    reply_to = analysis['details'].get('reply_to', '')
    if reply_to and reply_to.lower() != 'none' and from_addr:
        reply_domain = reply_to.split('@')[-1].lower() if '@' in reply_to else ''
        from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ''
        if reply_domain and from_domain and reply_domain != from_domain:
            flags.append({'severity': 'high', 'tab': 'details', 'message': f'Reply-To domain ({reply_domain}) differs from From domain ({from_domain})'})

    # Check attachments
    for att in analysis.get('attachments', []):
        if att['file_type'] in ('EXE', 'SCR', 'BAT', 'CMD', 'PS1', 'VBS', 'JS', 'WSF', 'HTA'):
            flags.append({'severity': 'high', 'tab': 'attachments', 'message': f'Dangerous file type: {att["filename"]}'})
        if att.get('ole_indicators'):
            for indicator in att['ole_indicators']:
                flags.append({'severity': 'high', 'tab': 'attachments', 'message': f'{indicator} detected in {att["filename"]}'})
        if att['file_type'] in ('DOCM', 'XLSM', 'PPTM'):
            flags.append({'severity': 'high', 'tab': 'attachments', 'message': f'Macro-enabled file: {att["filename"]}'})

    # Check for suspicious subject keywords
    subject = analysis['details'].get('subject', '').lower()
    urgency_words = ['urgent', 'immediate', 'action required', 'suspended', 'verify', 'confirm your', 'unusual activity']
    for word in urgency_words:
        if word in subject:
            flags.append({'severity': 'low', 'tab': 'details', 'message': f'Urgency keyword in subject: "{word}"'})
            break

    return flags


def analyze_eml(filepath):
    """Main analysis function - parses an .eml file and returns structured data."""
    with open(filepath, 'rb') as f:
        raw_bytes = f.read()

    # Try default policy first, fall back to compat32 for non-standard encodings
    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        # Test that we can access the payload without error
        if not msg.is_multipart():
            msg.get_payload(decode=True)
    except Exception:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)

    # Parse basic details
    from_full = decode_header_value(msg.get('From', ''))
    display_name, from_address = parseaddr(from_full)
    to_full = decode_header_value(msg.get('To', ''))
    _, to_address = parseaddr(to_full)

    subject = decode_header_value(msg.get('Subject', ''))
    date_raw = msg.get('Date', '')
    message_id = msg.get('Message-ID', '')
    return_path_raw = msg.get('Return-Path', '')
    _, return_path = parseaddr(return_path_raw)
    reply_to_raw = decode_header_value(msg.get('Reply-To', ''))
    _, reply_to = parseaddr(reply_to_raw) if reply_to_raw else ('', '')
    cc = decode_header_value(msg.get('Cc', ''))
    in_reply_to = msg.get('In-Reply-To', '')
    importance = msg.get('Importance', '') or msg.get('X-Priority', '')
    sender = msg.get('Sender', '')

    # Parse timestamp
    timestamp = ''
    try:
        dt = parsedate_to_datetime(date_raw)
        timestamp = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        timestamp = date_raw

    # Originating IP from X-Sender-IP or first Received
    originating_ip = msg.get('X-Sender-IP', '') or msg.get('X-Originating-IP', '')
    if originating_ip:
        originating_ip = originating_ip.strip('[]')

    # rDNS from Received-SPF or first external Received header
    rdns = ''
    received_spf = msg.get('Received-SPF', '')
    if received_spf:
        helo_match = re.search(r'helo=([^\s;]+)', received_spf)
        if helo_match:
            rdns = helo_match.group(1)

    # Get body content
    body = get_body_content(msg, raw_bytes)

    # Extract URLs from all body content
    urls_text = extract_urls(body['plaintext'])
    urls_html = extract_urls_from_html(body['html'])
    all_urls = sorted(set(urls_text + urls_html))

    # Get authentication
    authentication = extract_authentication_results(msg)

    # Get transmission hops
    hops = parse_received_hops(msg)

    # Get attachments
    attachments = extract_attachments(msg)

    # Get X-headers
    xheaders = extract_xheaders(msg)

    analysis = {
        'details': {
            'from_full': from_full,
            'from_address': from_address,
            'display_name': display_name,
            'sender': sender or None,
            'to': to_address or to_full,
            'cc': cc or None,
            'in_reply_to': in_reply_to or None,
            'timestamp': timestamp,
            'date_raw': date_raw,
            'reply_to': reply_to or None,
            'message_id': message_id,
            'return_path': return_path,
            'originating_ip': originating_ip or None,
            'rdns': rdns or None,
            'importance': importance or None,
            'subject': subject,
        },
        'authentication': authentication,
        'urls': all_urls,
        'attachments': attachments,
        'transmission': hops,
        'xheaders': xheaders,
        'body': body,
    }

    # Detect flags
    analysis['flags'] = detect_flags(analysis)

    # Count flags per tab
    tab_flags = {}
    for flag in analysis['flags']:
        tab = flag['tab']
        if tab not in tab_flags:
            tab_flags[tab] = {'high': 0, 'medium': 0, 'low': 0}
        tab_flags[tab][flag['severity']] += 1
    analysis['tab_flags'] = tab_flags

    return analysis


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Supported: .eml, .msg, .txt'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    return jsonify({'redirect': url_for('analyze', filename=filename)})


@app.route('/analyze/<filename>')
def analyze(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
    if not os.path.exists(filepath):
        return "File not found", 404

    try:
        analysis = analyze_eml(filepath)
    except Exception as e:
        return f"Error analyzing email: {str(e)}", 500

    return render_template('analyze.html', analysis=analysis, filename=filename)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=True)
