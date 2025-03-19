# socks-checker

This script is designed to check the validity of SOCKS proxies from a given input file and save the working proxies to an output file. It supports both SOCKS4 and SOCKS5 proxies and uses multithreading to check multiple proxies concurrently. The script also provides real-time progress updates, including the percentage of proxies checked and the status of each proxy (valid, invalid, or timeout).

Key Features:

1. Proxy Validation: The script checks if a proxy is valid by attempting to establish a connection and verifying if it supports SOCKS4 or SOCKS5.
2. Multithreading: It uses multiple threads to check proxies concurrently, speeding up the validation process.
3. Progress Tracking: The script displays the progress of the proxy checking process, including the percentage of proxies checked and the status of each proxy.
4. Output File: Valid proxies are saved to an output file for later use.

Example Usage:

    python proxy_checker.py -i proxies.txt -o working_proxies.txt
