import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, Output

class TestOutput(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron('localhost', 'user', 'pass')
        self.lutron._conn.send = MagicMock()
        self.output = Output(self.lutron, "Ceiling Light", 100, "DIMMER", 1, "UUID-1")

    def test_properties(self):
        self.assertEqual(self.output.name, "Ceiling Light")
        self.assertEqual(self.output.watts, 100)
        self.assertEqual(self.output.type, "DIMMER")
        self.assertEqual(self.output.id, 1)

    def test_is_dimmable(self):
        # DIMMER should be dimmable
        self.assertTrue(self.output.is_dimmable)
        
        # NON_DIM should not be dimmable
        non_dim = Output(self.lutron, "Fan", 100, "NON_DIM", 2, "UUID-2")
        self.assertFalse(non_dim.is_dimmable)

    def test_set_level_executes_command(self):
        self.output.level = 50.0
        # Verify that setting the level sends the correct command without fade time
        self.lutron._conn.send.assert_called_with('#OUTPUT,1,1,50.00')
        self.assertEqual(self.output.last_level(), 50.0)

    def test_handle_update(self):
        # Simulate receiving an update from the controller
        # Action 1 (ZONE_LEVEL), Level 75.00
        handled = self.output.handle_update(['1', '75.00'])
        self.assertTrue(handled)
        self.assertEqual(self.output.last_level(), 75.0)

if __name__ == '__main__':
    unittest.main()
