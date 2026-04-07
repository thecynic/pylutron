from typing import Iterable
from . import Area, Output, Keypad, MotionSensor

def print_all_devices(areas: Iterable[Area]):
    """Prints all detected devices and their attributes from the given areas."""
    for area in areas:
        print(f"Area: {area.name} (Integration ID: {area.id})")
        
        # Outputs (Lights, Dimmers, Shades, Motors)
        for output in area.outputs:
            print(f"  - Device: {output.name}")
            print(f"    Integration ID: {output.id}")
            print(f"    XML Type:       {output.type}")
            print(f"    Pylutron Class: {output.__class__.__name__}")
        
        # Keypads
        for keypad in area.keypads:
            print(f"  - Device: {keypad.name}")
            print(f"    Integration ID: {keypad.id}")
            print(f"    XML Type:       {keypad.type}")
            print(f"    Pylutron Class: {keypad.__class__.__name__}")
            
        # Sensors
        for sensor in area.sensors:
            print(f"  - Device: {sensor.name}")
            print(f"    Integration ID: {sensor.id}")
            print(f"    XML Type:       MOTION_SENSOR")
            print(f"    Pylutron Class: {sensor.__class__.__name__}")
        
        print("-" * 20)
