import nmap
import socket
import requests
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


# ------------------- Network Scanner -------------------
def scan_network(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sV')
    results = []
    for host in nm.all_hosts():
        results.append(f"Host: {host} ({nm[host].hostname()})")
        results.append(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            results.append(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                results.append(f"Port: {port}, State: {nm[host][proto][port]['state']}, Service: {nm[host][proto][port]['name']}")
    return results


# ------------------- Website Scanner -------------------
def scan_website(url):
    results = []
    try:
        response = requests.get(url, timeout=5)
        results.append(f"URL: {url}")
        results.append(f"Status Code: {response.status_code}")
        results.append(f"Headers:")
        for header, value in response.headers.items():
            results.append(f"{header}: {value}")
    except Exception as e:
        results.append(f"Error scanning {url}: {str(e)}")
    return results


# ------------------- IP Scanner -------------------
def scan_ip(ip):
    results = []
    try:
        host = socket.gethostbyaddr(ip)
        results.append(f"IP Address: {ip}")
        results.append(f"Hostname: {host[0]}")
    except Exception:
        results.append(f"IP Address: {ip} - Hostname not found")
    return results


# ------------------- PDF Report Generator -------------------
def generate_pdf(report_data, filename="network_report.pdf"):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(filename, pagesize=A4)
    story = []

    story.append(Paragraph("Automated Network & Website Scan Report", styles['Title']))
    story.append(Spacer(1, 20))

    for section, data in report_data.items():
        story.append(Paragraph(f"<b>{section}</b>", styles['Heading2']))
        story.append(Spacer(1, 12))
        for line in data:
            story.append(Paragraph(line, styles['Normal']))
        story.append(Spacer(1, 20))

    doc.build(story)
    print(f"[+] Report saved as {filename}")


# ------------------- Main -------------------
if __name__ == "__main__":
    print("Choose an option:")
    print("1. Scan Website")
    print("2. Scan IP / Network")
    choice = input("Enter choice (1 or 2): ")

    report_data = {}

    if choice == "1":
        website = input("Enter website URL (e.g. https://example.com): ")
        print("\n[+] Scanning Website...")
        website_results = scan_website(website)
        report_data["Website Scan Results"] = website_results

    elif choice == "2":
        target_ip = input("Enter target IP (e.g. 192.168.1.1 or 192.168.1.0/24): ")
        print("\n[+] Scanning Network...")
        network_results = scan_network(target_ip)
        print("\n[+] Scanning IP...")
        ip_results = scan_ip(target_ip)

        report_data["Network Scan Results"] = network_results
        report_data["IP Scan Results"] = ip_results

    else:
        print("Invalid choice! Exiting...")
        exit()

    # Generate PDF
    generate_pdf(report_data)
