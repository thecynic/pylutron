import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, Keypad, Led

class TestLed(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron("1.1.1.1", "user", "pass")
        self.lutron._conn = MagicMock()
        self.lutron.register_id = MagicMock()
        # Create a mock keypad
        self.keypad = Keypad(self.lutron, "Hallway Keypad", "SEETOUCH_KEYPAD", "Hallway", 100, "uuid-keypad")
        # Create an LED
        self.led = Led(self.lutron, self.keypad, "Status LED", 1, 81, "uuid-led")
        self.keypad.add_led(self.led)

    def test_initial_state(self):
        # Default state is False
        self.assertFalse(self.led.last_state)

    def test_query_state(self):
        # Verify that the LED state query sends the correct command to the controller
        self.led._Led__do_query_state()
        self.lutron._conn.send.assert_called_with('?DEVICE,100,81,9')

    def test_set_state(self):
        # Verify turning LED On
        self.led.state = True
        self.lutron._conn.send.assert_called_with('#DEVICE,100,81,9,1')
        self.assertTrue(self.led.last_state)
        
        # Verify turning LED Off
        self.led.state = False
        self.lutron._conn.send.assert_called_with('#DEVICE,100,81,9,0')
        self.assertFalse(self.led.last_state)

    def test_handle_update(self):
        # Simulate an LED state update arriving from the controller
        # Action 9 (LED_STATE), Params [1] (On)
        handled = self.led.handle_update(9, [1])
        self.assertTrue(handled)
        self.assertTrue(self.led.last_state)
        
        # Action 9 (LED_STATE), Params [0] (Off)
        handled = self.led.handle_update(9, [0])
        self.assertTrue(handled)
        self.assertFalse(self.led.last_state)
        
    def test_handle_update_invalid(self):
        # Wrong action
        handled = self.led.handle_update(99, [1])
        self.assertFalse(handled)
        
        # Missing params
        handled = self.led.handle_update(9, [])
        self.assertFalse(handled)

if __name__ == '__main__':
    unittest.main()
