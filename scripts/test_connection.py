#!/usr/bin/env python3
import argparse
import logging
import sys
import time
import os
import getpass

# Add the parent directory to sys.path so we can import pylutron
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pylutron import Lutron
from pylutron.debug import print_all_devices

def main():
    parser = argparse.ArgumentParser(description='Test connection to Lutron repeater')
    parser.add_argument('--host', help='IP address of the Lutron repeater')
    parser.add_argument('--user', help='Username')
    parser.add_argument('--password', help='Password')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s %(name)s %(message)s')

    host = args.host
    user = args.user
    password = args.password

    if not host:
        host = input('Enter Lutron repeater IP: ')
    if not user:
        user = input('Enter username [lutron]: ') or 'lutron'
    if not password:
        password = getpass.getpass('Enter password [lutron]: ') or 'lutron'

    print(f"Connecting to {host} as {user}...")
    lutron = Lutron(host, user, password)

    try:
        print("Loading XML database...")
        lutron.load_xml_db()
        print(f"Successfully loaded XML DB. Project name: {lutron.name}")
        print(f"Found {len(lutron.areas)} areas.")

        print("Connecting to telnet interface...")
        lutron.connect()
        print("Connected!")

        # Wait a bit for some potential updates
        print("Waiting 5 seconds for status updates...")
        time.sleep(5)

        print("\nTest summary:")
        print(f"GUID: {lutron.guid}")
        print_all_devices(lutron.areas)

        print("\nConnection test successful!")

    except Exception as e:
        print(f"\nError: {e}")
        # logging.exception("Connection test failed")
        sys.exit(1)

if __name__ == '__main__':
    main()
