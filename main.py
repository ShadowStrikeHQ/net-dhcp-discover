#!/usr/bin/env python3

import argparse
import socket
import logging
import sys
import time
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, conf

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Perform DHCP discovery to identify rogue DHCP servers.")
    parser.add_argument("-i", "--interface", dest="interface", default=None,
                        help="Network interface to use (e.g., eth0, wlan0). If not specified, tries to find one automatically.")
    parser.add_argument("-t", "--timeout", dest="timeout", type=int, default=5,
                        help="Timeout in seconds to wait for DHCP responses. Default is 5 seconds.")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Enable verbose output for debugging.")
    return parser

def discover_dhcp(interface, timeout):
    """
    Performs DHCP discovery to identify DHCP servers on the network.

    Args:
        interface (str): The network interface to use.
        timeout (int): Timeout in seconds to wait for DHCP responses.

    Returns:
        list: A list of DHCP server IP addresses discovered.
    """

    dhcp_servers = []

    # Create a DHCP Discover packet
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=b"\x00\x0c\x29\x00\x00\x00")/DHCP(options=[("message-type","discover"), "end"])

    try:
        logging.info(f"Sending DHCP Discover packet on interface {interface}...")
        # Send the DHCP Discover packet
        sendp(dhcp_discover, iface=interface, verbose=False)

        # Sniff for DHCP Offer packets
        logging.info(f"Sniffing for DHCP Offer packets on interface {interface} for {timeout} seconds...")
        responses = sniff(filter="udp and port 68", iface=interface, timeout=timeout)

        # Process the responses
        for packet in responses:
            if DHCP in packet and packet[DHCP].options[0][1] == 2:  # DHCP Offer
                server_ip = packet[IP].src
                if server_ip not in dhcp_servers:
                    dhcp_servers.append(server_ip)
                    logging.info(f"Found DHCP server: {server_ip}")

    except socket.error as e:
        logging.error(f"Socket error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

    if not dhcp_servers:
        logging.info("No DHCP servers found.")

    return dhcp_servers

def main():
    """
    Main function to parse arguments and run the DHCP discovery process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    interface = args.interface
    if not interface:
        try:
            # Attempt to determine interface automatically. This might not work on all systems.
            interface = conf.iface
            logging.info(f"No interface specified. Using default interface: {interface}")
        except Exception as e:
            logging.error("Could not determine default interface. Please specify an interface using -i/--interface.")
            sys.exit(1)

    if not interface:
        logging.error("No network interface specified. Please specify an interface using -i/--interface.")
        sys.exit(1)

    if not isinstance(args.timeout, int) or args.timeout <= 0:
        logging.error("Timeout must be a positive integer.")
        sys.exit(1)

    try:
        dhcp_servers = discover_dhcp(interface, args.timeout)

        if dhcp_servers:
            print("\nDHCP Servers Found:")
            for server in dhcp_servers:
                print(f"- {server}")
        else:
            print("No DHCP servers found.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

# Usage Examples:

# 1. Basic DHCP discovery on eth0 with default timeout (5 seconds):
#    python net_dhcp_discover.py -i eth0

# 2. DHCP discovery on wlan0 with a timeout of 10 seconds:
#    python net_dhcp_discover.py -i wlan0 -t 10

# 3. DHCP discovery with verbose output for debugging:
#    python net_dhcp_discover.py -i eth0 -v

# Note:  This script requires root privileges or appropriate capabilities
#        to send and receive raw packets. Use with caution and ensure you
#        understand the legal implications of network scanning in your jurisdiction.