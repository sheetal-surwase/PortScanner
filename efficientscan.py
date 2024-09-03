import socket
from concurrent.futures import ThreadPoolExecutor

def scan(target, ports):
    print('\n' + 'Starting Scan For ' + str(target))
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(1, ports):
            executor.submit(scan_port, target, port)

def scan_port(ipaddress, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ipaddress, port))
            if result == 0:
                print(f"[+] Port {port} is open on {ipaddress}")
    except socket.error as e:
        print(f"[-] Error scanning {ipaddress}:{port} - {e}")
    except Exception as e:
        print(f"[-] Unexpected error scanning {ipaddress}:{port} - {e}")

def main():
    targets = input("[*] Enter Targets To Scan (split them by ,): ")
    ports = int(input("[*] Enter Number of Ports You Want To Scan (e.g., 100): "))
    
    if ',' in targets:
        print("[*] Scanning Multiple Targets")
        for ip_addr in targets.split(','):
            scan(ip_addr.strip(), ports)
    else:
        scan(targets.strip(), ports)

if __name__ == "__main__":
    main()
