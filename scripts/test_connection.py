#!/usr/bin/env python3
import argparse
import logging
import sys
import time
from pylutron import Lutron

def main():
    parser = argparse.ArgumentParser(description='Test connection to Lutron repeater')
    parser.add_argument('--host', help='IP address of the Lutron repeater')
    parser.add_argument('--user', help='Username (default: lutron)', default='lutron')
    parser.add_argument('--password', help='Password (default: lutron)', default='lutron')
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
        password = input('Enter password [lutron]: ') or 'lutron'

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
        for area in lutron.areas:
            print(f"Area: {area.name} (ID: {area.id})")
            for output in area.outputs:
                print(f"  Output: {output.name} (ID: {output.id}, Level: {output.last_level()})")
            for keypad in area.keypads:
                print(f"  Keypad: {keypad.name} (ID: {keypad.id})")

        print("\nConnection test successful!")

    except Exception as e:
        print(f"\nError: {e}")
        logging.exception("Connection test failed")
        sys.exit(1)

if __name__ == '__main__':
    main()
