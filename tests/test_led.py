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
        self.keypad = Keypad(self.lutron, "Hallway Keypad", "SEETOUCH_KEYPAD", "Hallway", 100, "uuid-keypad")
        # Create an LED
        self.led = Led(self.lutron, self.keypad, "Status LED", 1, 81, "uuid-led")
        self.keypad.add_led(self.led)

    def test_initial_state(self) -> None:
        # Default state is False
        self.assertFalse(self.led.last_state)

    def test_query_state(self) -> None:
        # Verify that the LED state query sends the correct command to the controller
        self.led._do_query_state()
        cast(MagicMock, self.lutron._conn.send).assert_called_with('?DEVICE,100,81,9')

    def test_set_state(self) -> None:
        # Verify turning LED On
        self.led.state = True
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#DEVICE,100,81,9,1')
        self.assertTrue(self.led.last_state)
        
        # Verify turning LED Off
        self.led.state = False
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#DEVICE,100,81,9,0')
        self.assertFalse(self.led.last_state)

    def test_handle_update(self) -> None:
        # Simulate an LED state update arriving from the controller
        # Action 9 (LED_STATE), Params [1] (On)
        handled = self.led.handle_update(9, [1])
        self.assertTrue(handled)
        self.assertTrue(self.led.last_state)
        
        # Action 9 (LED_STATE), Params [0] (Off)
        handled = self.led.handle_update(9, [0])
        self.assertTrue(handled)
        self.assertFalse(self.led.last_state)
        
    def test_handle_update_invalid(self) -> None:
        # Wrong action
        handled = self.led.handle_update(99, [1])
        self.assertFalse(handled)
        
        # Missing params
        handled = self.led.handle_update(9, [])
        self.assertFalse(handled)

if __name__ == '__main__':
    unittest.main()
