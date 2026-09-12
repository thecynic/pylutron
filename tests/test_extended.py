import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, LutronXmlDbParser, Button, Keypad, LutronEntity, LutronEvent, Output

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
                                            <Button Engraving="On" ButtonType="Toggle" UUID="7502" />
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
                                            <Button Engraving="Raise" ButtonType="SingleSceneRaiseLower" Direction="Raise" UUID="9556" />
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

from typing import Any, cast

class TestExtendedCoverage(unittest.TestCase):
    def setUp(self) -> None:
        self.lutron = Lutron('localhost', 'user', 'pass')
        self.lutron._conn = MagicMock()

    def test_legacy_subscription(self) -> None:
        """Test #5: Legacy Lutron.subscribe (deprecated)"""
        # Create a dummy entity
        entity = LutronEntity(self.lutron, "Test Entity", "601")
        handler = MagicMock()
        
        # This should trigger a warning but function correctly
        self.lutron.subscribe(entity, handler)
        
        # Simulate an event dispatch from the entity
        # The legacy dispatcher in Lutron class handles this
        entity._dispatch_event(cast(Any, None), {})
        
        self.assertTrue(handler.called)
        self.assertEqual(handler.call_args[0][0], entity)

    def test_palladiom_keypad_parsing(self) -> None:
        """Test #2: Specific Keypad Types (PALLADIOM_KEYPAD)"""
        parser = LutronXmlDbParser(self.lutron, LEGACY_AND_COMPLEX_XML)
        parser.parse()
        
        mbr = next(a for a in parser.areas if a.name == "Master Bedroom")
        keypad = mbr.keypads[0]
        self.assertEqual(keypad.type, "PALLADIOM_KEYPAD")
        self.assertEqual(len(keypad.buttons), 1)

    def test_pico_raise_lower_naming(self) -> None:
        """Test #3: Naming logic for Raise/Lower buttons"""
        parser = LutronXmlDbParser(self.lutron, LEGACY_AND_COMPLEX_XML)
        parser.parse()
        
        kitchen = next(a for a in parser.areas if a.name == "Kitchen")
        pico = kitchen.keypads[0]
        # SingleSceneRaiseLower buttons get "Dimmer " prepended if they are Raise/Lower
        btn = pico.buttons[0]
        self.assertEqual(btn.name, "Dimmer Raise")

    def test_request_helper_logic(self) -> None:
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

    def test_shade_commands(self) -> None:
        from pylutron import Shade
        shade = Shade(self.lutron, "Main Shade", 0, "SYSTEM_SHADE", 50, "2001")
        
        shade.start_raise()
        cast(MagicMock, self.lutron._conn.send).assert_called_with("#OUTPUT,50,2")
        
        shade.start_lower()
        cast(MagicMock, self.lutron._conn.send).assert_called_with("#OUTPUT,50,3")
        
        shade.stop()
        cast(MagicMock, self.lutron._conn.send).assert_called_with("#OUTPUT,50,4")

    def test_output_flash(self) -> None:
        from pylutron import Output
        output = Output(self.lutron, "Light", 100, "DIMMER", 10, "714")
        output.flash()
        cast(MagicMock, self.lutron._conn.send).assert_called_with("#OUTPUT,10,5")

    def test_motion_sensor_battery_status(self) -> None:
        from pylutron import MotionSensor, PowerSource, BatteryStatus
        import time
        sensor = MotionSensor(self.lutron, "Sensor", 500, "900")
        
        # Mock handle_update to set values
        # args: _, action, _, power, battery, _
        # power: 1 -> BATTERY
        # battery: 2 -> LOW (original enum values restored: NORMAL=1, LOW=2, OTHER=3)
        sensor.handle_update(['DEVICE', '22', '1', '1', '2', '0']) 
        
        self.assertEqual(sensor.power_source, PowerSource.BATTERY)
        self.assertEqual(sensor.battery_status, BatteryStatus.LOW)
        self.assertEqual(sensor.id, 500)
        self.assertEqual(sensor.legacy_uuid, "500")
        
        # Test __str__ and __repr__
        self.assertIn("Sensor", str(sensor))
        self.assertIn("battery", repr(sensor))

    def test_integration_id_exists_error(self) -> None:
        from pylutron import IntegrationIdExistsError, Output
        output = Output(self.lutron, "Light", 100, "DIMMER", 10, "714")
        # Registering the same ID again should raise
        with self.assertRaises(IntegrationIdExistsError):
            self.lutron.register_id(Output._CMD_TYPE, output)


class TestDispatchDuringUnsubscribe(unittest.TestCase):
    """Unsubscribing while an event is being dispatched must not skip anyone."""

    def test_unsubscribing_handler_does_not_skip_the_next_subscriber(self) -> None:
        """_dispatch_event iterated the live list, so a removal skipped an element.

        Reproduced deterministically here by having the first handler unsubscribe
        itself, which is the same list mutation Home Assistant performs from its
        own thread when an entity is removed (async_on_remove fires pylutron's
        unsubscribe callable while the reader thread may be dispatching).

        Without the snapshot, removing index 0 mid-iteration shifts the list and
        the loop jumps straight to 'third' -- 'second' silently never fires.
        """
        lutron = Lutron('127.0.0.1', 'user', 'pass')
        entity = LutronEntity(lutron, 'Test Entity', 'uuid-1')
        called = []
        unsub = {}

        def first(obj, context, event, params):
            called.append('first')
            unsub['first']()

        def second(obj, context, event, params):
            called.append('second')

        def third(obj, context, event, params):
            called.append('third')

        unsub['first'] = entity.subscribe(first, None)
        entity.subscribe(second, None)
        entity.subscribe(third, None)

        entity._dispatch_event(Output.Event.LEVEL_CHANGED, {'level': 50.0})

        self.assertEqual(called, ['first', 'second', 'third'],
                         "a subscriber was skipped when another unsubscribed mid-dispatch")
        # The removal still took effect for subsequent events.
        called.clear()
        entity._dispatch_event(Output.Event.LEVEL_CHANGED, {'level': 60.0})
        self.assertEqual(called, ['second', 'third'])


if __name__ == '__main__':
    unittest.main()
