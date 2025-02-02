import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def check_ssl_certificate(url):
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    port = 443
    
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((host, port), timeout=10) as conn:
            with context.wrap_socket(conn, server_hostname=host) as ssock:
                ssl_info = ssock.getpeercert()
                
                cert_expiry = ssl_info.get('notAfter')
                cert_expiry_date = datetime.strptime(cert_expiry, "%b %d %H:%M:%S %Y GMT")
                
                if cert_expiry_date < datetime.now():
                    return 40
                
                if not ssl_info:
                    return 50
                
                time_left = (cert_expiry_date - datetime.now()).days
                score = 80 + min(time_left // 5, 20)
                return score
                
    except Exception as e:
        print(f"SSL error for {url}: {e}")
        return 20

if __name__ == "__main__":
    url = input("Enter the URL to check: ")

    ssl_score = check_ssl_certificate(url)

    if ssl_score >= 90:
        print(f"The URL '{url}' has a valid SSL certificate and is legitimate (SSL Score: {ssl_score}).")
    elif ssl_score >= 40:
        print(f"The URL '{url}' has a valid SSL certificate but issues were detected (SSL Score: {ssl_score}).")
    else:
        print(f"The URL '{url}' has an invalid or expired SSL certificate and is considered phishing (SSL Score: {ssl_score}).")
