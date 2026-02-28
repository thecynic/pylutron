import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, Keypad, Button, Led

class TestKeypad(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron("1.1.1.1", "user", "pass")
        # Mock the connection to avoid actual network calls
        self.lutron._conn = MagicMock()
        # Mock the register_id method to avoid errors during object creation if they try to register
        self.lutron.register_id = MagicMock()
        
        self.keypad = Keypad(self.lutron, "Main Keypad", "SEETOUCH_KEYPAD", "Hallway", 100, "uuid-100")

    def test_button_press(self):
        button = Button(self.lutron, self.keypad, "Btn 1", 1, "Toggle", "Press", "uuid-btn-1")
        self.keypad.add_button(button)
        
        # Verify that pressing the button sends the correct command
        button.press()
        # Command format: #DEVICE,integration_id,component_num,action
        self.lutron._conn.send.assert_called_with('#DEVICE,100,1,3')
        
    def test_led_state_update(self):
        led = Led(self.lutron, self.keypad, "Led 1", 1, 81, "uuid-led-1")
        self.keypad.add_led(led)
        
        # Verify that setting the LED state sends the correct command
        led.state = True
        self.lutron._conn.send.assert_called() 
        args = self.lutron._conn.send.call_args[0][0]
        self.assertTrue(args.startswith("#DEVICE,100"))
        
    def test_handle_update(self):
        button = Button(self.lutron, self.keypad, "Btn 1", 1, "Toggle", "Press", "uuid-btn-1")
        self.keypad.add_button(button)
        
        handler = MagicMock()
        button.subscribe(handler, None)
        
        # Simulate a button press event arriving from the controller
        self.keypad.handle_update(['1', '3']) # Component 1, Action 3 (Press)
        
        # Verify that the subscriber was notified with the correct event
        self.assertTrue(handler.called)
        call_args = handler.call_args
        self.assertEqual(call_args[0][0], button) 
        self.assertEqual(call_args[0][2], Button.Event.PRESSED)
