#!/usr/bin/env python3
import sys
import os

# Add the parent directory to sys.path so we can import pylutron
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pylutron import Lutron, LutronXmlDbParser
from pylutron.debug import print_all_devices

def debug_xml(xml_file):
    if not os.path.exists(xml_file):
        print(f"Error: File {xml_file} not found.")
        sys.exit(1)

    with open(xml_file, 'rb') as f:
        xml_data = f.read()
    
    # Dummy Lutron object to satisfy the parser
    lutron = Lutron('localhost', 'user', 'password')
    parser = LutronXmlDbParser(lutron, xml_data)
    
    if not parser.parse():
        print("Error: Failed to parse XML.")
        sys.exit(1)

    print(f"Project Name: {parser.project_name}")
    print("=" * 40)

    print_all_devices(parser.areas)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_xml_file>")
        sys.exit(1)
    
    debug_xml(sys.argv[1])
