import socket
import threading
import time
import sys
import re
import queue
import struct
import argparse
import os

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

checked_count = 0
checked_count_lock = threading.Lock()

def isSocks4(host, port, soc):
    ipaddr = socket.inet_aton(host)
    port_pack = struct.pack(">H", port)
    packet4 = b"\x04\x01" + port_pack + ipaddr + b"\x00"
    soc.sendall(packet4)
    data = soc.recv(8)
    if len(data) < 2:
        return False
    if data[0] != 0x00:
        return False
    if data[1] != 0x5A:
        return False
    return True

def isSocks5(host, port, soc):
    soc.sendall(b"\x05\x01\x00")
    data = soc.recv(2)
    if len(data) < 2:
        return False
    if data[0] != 0x05:
        return False
    if data[1] != 0x00:
        return False
    return True

def getSocksVersion(proxy, timeout):
    host, port = proxy.split(":")
    try:
        port = int(port)
        if port < 0 or port > 65536:
            return None
    except Exception:
        return None

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if isSocks4(host, port, s):
            s.close()
            return 4
        elif isSocks5(host, port, s):
            s.close()
            return 5
        else:
            s.close()
            return None
    except socket.timeout:
        s.close()
        return "timeout"
    except socket.error:
        s.close()
        return None

class ThreadChecker(threading.Thread):
    def __init__(self, queue, timeout, total_proxies, workingProxies):
        self.timeout = timeout
        self.q = queue
        self.total_proxies = total_proxies
        self.workingProxies = workingProxies
        threading.Thread.__init__(self)

    def run(self):
        global checked_count
        while True:
            proxy = self.q.get()
            version = getSocksVersion(proxy, self.timeout)
            with checked_count_lock:
                checked_count += 1
                current_count = checked_count
            percentage = (current_count / self.total_proxies) * 100
            if version in [5, 4]:
                print(f"[ {percentage:.1f}% ]{Colors.GREEN}[ + ] {proxy} - SOCKS{version}{Colors.RESET}")
                self.workingProxies.put(proxy)
            elif version == "timeout":
                print(f"[ {percentage:.1f}% ]{Colors.YELLOW}[ ! ] {proxy} - Timeout{Colors.RESET}")
            else:
                print(f"[ {percentage:.1f}% ]{Colors.RED}[ - ] {proxy} - Invalid{Colors.RESET}")
            self.q.task_done()

class ThreadWriter(threading.Thread):
    def __init__(self, queue, outputPath):
        self.q = queue
        self.outputPath = outputPath
        threading.Thread.__init__(self)

    def run(self):
        while True:
            toWrite = self.q.qsize()
            with open(self.outputPath, "a+") as outputFile:
                for _ in range(toWrite):
                    proxy = self.q.get()
                    outputFile.write(proxy + "\n")
                    self.q.task_done()
            time.sleep(5)

def getProxiesFromFile(filePath):
    pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}"
    data = ""
    try:
        with open(filePath) as file:
            data = file.read() + "\n"
    except Exception:
        print(f"{Colors.RED}Error reading file: {filePath}{Colors.RESET}")
        return []
    return re.findall(pattern, data)

def count_lines_in_file(filePath):
    try:
        with open(filePath, "r") as file:
            return sum(1 for line in file)
    except Exception:
        return 0

def main():
    parser = argparse.ArgumentParser(description="Check valid SOCKS proxies")
    parser.add_argument("-i", "--input", required=True, help="Input file containing proxies")
    parser.add_argument("-o", "--output", default="working_proxies.txt", help="Output file to save working proxies")
    parser.add_argument("-th", "--thread", type=int, default=30, help="Number of concurrent threads")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Timeout in seconds for each connection")
    args = parser.parse_args()

    proxies = getProxiesFromFile(args.input)
    if not proxies:
        print(f"{Colors.RED}No proxies found or file read error!{Colors.RESET}")
        sys.exit(1)

    print(f"Loaded {len(proxies)} proxies")
    checkQueue = queue.Queue()
    workingProxies = queue.Queue()

    for proxy in proxies:
        checkQueue.put(proxy)

    for _ in range(args.thread):
        thread = ThreadChecker(checkQueue, args.timeout, len(proxies), workingProxies)
        thread.daemon = True
        thread.start()

    writer_thread = ThreadWriter(workingProxies, args.output)
    writer_thread.daemon = True
    writer_thread.start()

    checkQueue.join()
    workingProxies.join()

    working_proxy_count = count_lines_in_file(args.output)
    print(f"\n[+] Checking completed!")
    print(f"[+] Total working proxies: {working_proxy_count}")
    sys.exit(0)

if __name__ == "__main__":
    main()
