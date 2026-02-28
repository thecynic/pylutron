import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, Shade, Output

class TestShade(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron("1.1.1.1", "user", "pass")
        self.lutron._conn = MagicMock()
        # Mock register_id to avoid errors
        self.lutron.register_id = MagicMock()

    def test_shade_commands(self):
        # Create a shade (Output with type SYSTEM_SHADE or MOTOR)
        shade = Shade(self.lutron, "Master Shade", 100, "SYSTEM_SHADE", 50, "uuid-shade")
        
        # Test start_raise
        shade.start_raise()
        # Expect OP_EXECUTE, Output._CMD_TYPE, integration_id, Shade._ACTION_RAISE
        # #OUTPUT,50,2
        self.lutron._conn.send.assert_called_with('#OUTPUT,50,2')
        
        # Test start_lower
        shade.start_lower()
        self.lutron._conn.send.assert_called_with('#OUTPUT,50,3')
        
        # Test stop
        shade.stop()
        self.lutron._conn.send.assert_called_with('#OUTPUT,50,4')
