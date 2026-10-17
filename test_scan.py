import urllib.request
import json
import time

def test_scan():
    print("Initiating test scan...")
    req = urllib.request.Request(
        'http://127.0.0.1:5000/api/scan',
        data=json.dumps({
            'url': 'https://example.com',
            'scan_types': ['recon', 'vulnerabilities'],
            'use_selenium': False
        }).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(req, timeout=10)
    data = json.loads(res.read().decode('utf-8'))
    print("Scan response:", data)
    scan_id = data.get('scan_id')

    for i in range(40):
        time.sleep(1)
        st_res = urllib.request.urlopen(f'http://127.0.0.1:5000/api/scan/status/{scan_id}', timeout=5)
        st = json.loads(st_res.read().decode('utf-8'))
        print(f"[{i+1}s] Status: {st.get('status')} | Message: {st.get('current_message')}")
        if st.get('status') == 'completed':
            print("Completed successfully!")
            print(f"Total findings: {len(st.get('findings', []))}")
            print("Stats:", st.get('stats'))
            break
        elif st.get('status') == 'error':
            print("Error encountered:", st.get('error'))
            return

    for fmt in ['pdf', 'html', 'json']:
        try:
            rep = urllib.request.urlopen(f'http://127.0.0.1:5000/api/report/{scan_id}?format={fmt}', timeout=10)
            content = rep.read()
            print(f"Report format '{fmt}': status {rep.status}, size {len(content)} bytes")
        except Exception as e:
            print(f"Report format '{fmt}' error: {e}")

if __name__ == '__main__':
    test_scan()

