import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Callable

class NetProbeScanner:
    def __init__(self):
        self.open_ports = []
        self.closed_ports = []
    
    def scan_single_port(self, host: str, port: int, timeout: float = 0.08) -> Dict:
        """🚀 ULTRA-FAST port scan (0.08s timeout)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:  # OPEN
                return {
                    'port': port,
                    'status': 'OPEN',
                    'service': self.get_service(port)
                }
            else:  # CLOSED
                return {
                    'port': port,
                    'status': 'CLOSED',
                    'service': '-'
                }
        except:
            return {'port': port, 'status': 'CLOSED', 'service': '-'}
    
    def get_service(self, port: int) -> str:
        services = {
            21:'FTP', 22:'SSH', 80:'HTTP', 443:'HTTPS', 3306:'MySQL', 
            3389:'RDP', 8080:'HTTP-Alt', 53:'DNS', 25:'SMTP', 110:'POP3'
        }
        return services.get(port, '-')
    
    def get_port_list(self, scan_type: str) -> List[int]:
        """✅ SCANS ALL REQUESTED PORTS"""
        print(f"🔍 Scan type: {scan_type}")
        if "ALL PORTS (65,535)" in scan_type:
            print("🚀 FULL SCAN: 65,535 ports")
            return list(range(1, 65536))  # ALL 65K PORTS!
        elif "Intense (1-10K)" in scan_type:
            print("🔥 Intense scan: 10,000 ports")
            return list(range(1, 10001))
        elif "Top 100" in scan_type:
            print("⚡ Top 100 ports")
            return [21,22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,8080]
        else:  # Quick (1-1024)
            print("⚡ Quick scan: 1-1024")
            return list(range(1, 1025))
    
    def scan_with_callback(self, host: str, ports: List[int], callback: Callable, max_workers=100):
        """🚀 100 THREADS - ULTRA FAST"""
        print(f"🚀 Starting scan on {host} with {len(ports):,} ports, {max_workers} threads")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_single_port, host, port): port for port in ports}
            
            processed = 0
            for future in as_completed(futures):
                result = future.result()
                processed += 1
                progress = processed / len(ports)
                
                # Callback for UI update
                callback(result, progress, processed, len(ports))
        
        print(f"✅ Scan complete: {len(self.open_ports)} open ports found")
