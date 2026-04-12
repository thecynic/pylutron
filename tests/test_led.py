import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, Keypad, Led

from typing import cast

class TestLed(unittest.TestCase):
    def setUp(self) -> None:
        self.lutron = Lutron("1.1.1.1", "user", "pass")
        self.lutron._conn = MagicMock()
        self.lutron.register_id = MagicMock() # type: ignore[method-assign]
        # Create a mock keypad
        self.keypad = Keypad(self.lutron, "Hallway Keypad", "SEETOUCH_KEYPAD", "Hallway", 100, "800")
        # Create an LED
        self.led = Led(self.lutron, self.keypad, "Status LED", 1, 81, "803")
        self.keypad.add_led(self.led)

    def test_initial_state(self) -> None:
        # Default state is 0 (LED_OFF)
        self.assertEqual(self.led.last_state, Led.LED_OFF)

    def test_query_state(self) -> None:
        # Verify that the LED state query sends the correct command to the controller
        self.led._do_query_state()
        cast(MagicMock, self.lutron._conn.send).assert_called_with('?DEVICE,100,81,9')

    def test_set_state(self) -> None:
        # Verify turning LED On
        self.led.state = Led.LED_ON
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#DEVICE,100,81,9,1')
        self.assertEqual(self.led.last_state, Led.LED_ON)
        
        # Verify turning LED Off
        self.led.state = Led.LED_OFF
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#DEVICE,100,81,9,0')
        self.assertEqual(self.led.last_state, Led.LED_OFF)

        # Verify Slow Flash
        self.led.state = Led.LED_SLOW_FLASH
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#DEVICE,100,81,9,2')
        self.assertEqual(self.led.last_state, Led.LED_SLOW_FLASH)

        # Verify Fast Flash
        self.led.state = Led.LED_FAST_FLASH
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#DEVICE,100,81,9,3')
        self.assertEqual(self.led.last_state, Led.LED_FAST_FLASH)

    def test_set_state_invalid(self) -> None:
        # Verify that setting an invalid LED state raises a ValueError
        with self.assertRaises(ValueError):
            self.led.state = 4

    def test_handle_update(self) -> None:
        # Simulate an LED state update arriving from the controller
        # Action 9 (LED_STATE), Params [1] (On)
        handled = self.led.handle_update(9, [Led.LED_ON])
        self.assertTrue(handled)
        self.assertEqual(self.led.last_state, Led.LED_ON)
        
        # Action 9 (LED_STATE), Params [0] (Off)
        handled = self.led.handle_update(9, [Led.LED_OFF])
        self.assertTrue(handled)
        self.assertEqual(self.led.last_state, Led.LED_OFF)

        # Action 9 (LED_STATE), Params [2] (Slow Flash)
        handled = self.led.handle_update(9, [Led.LED_SLOW_FLASH])
        self.assertTrue(handled)
        self.assertEqual(self.led.last_state, Led.LED_SLOW_FLASH)
        
    def test_handle_update_invalid(self) -> None:
        # Wrong action
        handled = self.led.handle_update(99, [1])
        self.assertFalse(handled)
        
        # Missing params
        handled = self.led.handle_update(9, [])
        self.assertFalse(handled)

if __name__ == '__main__':
    unittest.main()
