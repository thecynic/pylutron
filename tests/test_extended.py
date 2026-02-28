import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, LutronXmlDbParser, Button, Keypad, LutronEntity, LutronEvent

# Anonymized XML based on the real DbXmlInfo.xml structure
LEGACY_AND_COMPLEX_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<Project>
    <ProjectName ProjectName="Anonymized House" UUID="1" />
    <GUID>7ccee645777f46459a3d5216b6e54d5a</GUID>
    <Areas>
        <Area Name="House" UUID="3" IntegrationID="0" OccupancyGroupAssignedToID="0" SortOrder="0">
            <Areas>
                <Area Name="Master Bedroom" UUID="407" IntegrationID="16" OccupancyGroupAssignedToID="409">
                    <DeviceGroups>
                        <DeviceGroup Name="Main">
                            <Devices>
                                <Device Name="Master Keypad" UUID="7501" IntegrationID="34" DeviceType="PALLADIOM_KEYPAD">
                                    <Components>
                                        <Component ComponentNumber="1" ComponentType="BUTTON">
                                            <Button Engraving="On" ButtonType="Toggle" UUID="B1" />
                                        </Component>
                                    </Components>
                                </Device>
                            </Devices>
                        </DeviceGroup>
                    </DeviceGroups>
                </Area>
                <Area Name="Kitchen" UUID="357" IntegrationID="11" OccupancyGroupAssignedToID="359">
                    <DeviceGroups>
                        <DeviceGroup Name="Stairs">
                            <Devices>
                                <Device Name="Pico" UUID="9555" IntegrationID="28" DeviceType="PICO_KEYPAD">
                                    <Components>
                                        <Component ComponentNumber="5" ComponentType="BUTTON">
                                            <Button Engraving="Raise" ButtonType="SingleSceneRaiseLower" Direction="Raise" UUID="B2" />
                                        </Component>
                                    </Components>
                                </Device>
                            </Devices>
                        </DeviceGroup>
                    </DeviceGroups>
                </Area>
            </Areas>
        </Area>
    </Areas>
    <OccupancyGroups>
        <OccupancyGroup UUID="409" OccupancyGroupNumber="409" />
        <OccupancyGroup UUID="359" OccupancyGroupNumber="359" />
    </OccupancyGroups>
</Project>
"""

class TestExtendedCoverage(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron('localhost', 'user', 'pass')
        self.lutron._conn = MagicMock()

    def test_legacy_subscription(self):
        """Test #5: Legacy Lutron.subscribe (deprecated)"""
        # Create a dummy entity
        entity = LutronEntity(self.lutron, "Test Entity", "uuid-1")
        handler = MagicMock()
        
        # This should trigger a warning but function correctly
        self.lutron.subscribe(entity, handler)
        
        # Simulate an event dispatch from the entity
        # The legacy dispatcher in Lutron class handles this
        entity._dispatch_event(None, {})
        
        self.assertTrue(handler.called)
        self.assertEqual(handler.call_args[0][0], entity)

    def test_palladiom_keypad_parsing(self):
        """Test #2: Specific Keypad Types (PALLADIOM_KEYPAD)"""
        parser = LutronXmlDbParser(self.lutron, LEGACY_AND_COMPLEX_XML)
        parser.parse()
        
        mbr = next(a for a in parser.areas if a.name == "Master Bedroom")
        keypad = mbr.keypads[0]
        self.assertEqual(keypad.type, "PALLADIOM_KEYPAD")
        self.assertEqual(len(keypad.buttons), 1)

    def test_pico_raise_lower_naming(self):
        """Test #3: Naming logic for Raise/Lower buttons"""
        parser = LutronXmlDbParser(self.lutron, LEGACY_AND_COMPLEX_XML)
        parser.parse()
        
        kitchen = next(a for a in parser.areas if a.name == "Kitchen")
        pico = kitchen.keypads[0]
        # SingleSceneRaiseLower buttons get "Dimmer " prepended if they are Raise/Lower
        btn = pico.buttons[0]
        self.assertEqual(btn.name, "Dimmer Raise")

    def test_request_helper_logic(self):
        """Coverage for _RequestHelper concurrency logic"""
        from pylutron import _RequestHelper
        helper = _RequestHelper()
        action = MagicMock()
        
        # Request 1
        ev1 = helper.request(action)
        # Request 2 (should not trigger action again)
        ev2 = helper.request(action)
        
        self.assertEqual(action.call_count, 1)
        self.assertFalse(ev1.is_set())
        
        helper.notify()
        self.assertTrue(ev1.is_set())
        self.assertTrue(ev2.is_set())

    def test_shade_commands(self):
        from pylutron import Shade
        shade = Shade(self.lutron, "Main Shade", 0, "SYSTEM_SHADE", 50, "uuid-shade")
        
        shade.start_raise()
        self.lutron._conn.send.assert_called_with("#OUTPUT,50,2")
        
        shade.start_lower()
        self.lutron._conn.send.assert_called_with("#OUTPUT,50,3")
        
        shade.stop()
        self.lutron._conn.send.assert_called_with("#OUTPUT,50,4")

    def test_output_flash(self):
        from pylutron import Output
        output = Output(self.lutron, "Light", 100, "DIMMER", 10, "uuid-light")
        output.flash()
        self.lutron._conn.send.assert_called_with("#OUTPUT,10,5")

    def test_motion_sensor_battery_status(self):
        from pylutron import MotionSensor, PowerSource, BatteryStatus
        import time
        sensor = MotionSensor(self.lutron, "Sensor", 500, "uuid-sensor")
        
        # Mock handle_update to set values
        # args: _, action, _, power, battery, _
        sensor.handle_update(['DEVICE', '22', '1', '1', '2', '0']) 
        
        self.assertEqual(sensor.power_source, PowerSource.BATTERY)
        self.assertEqual(sensor.battery_status, BatteryStatus.LOW)
        self.assertEqual(sensor.id, 500)
        self.assertEqual(sensor.legacy_uuid, "500")
        
        # Test __str__ and __repr__
        self.assertIn("Sensor", str(sensor))
        self.assertIn("battery", repr(sensor))

    def test_integration_id_exists_error(self):
        from pylutron import IntegrationIdExistsError, Output
        output = Output(self.lutron, "Light", 100, "DIMMER", 10, "uuid-light")
        # Registering the same ID again should raise
        with self.assertRaises(IntegrationIdExistsError):
            self.lutron.register_id(Output._CMD_TYPE, output)

if __name__ == '__main__':
    unittest.main()
