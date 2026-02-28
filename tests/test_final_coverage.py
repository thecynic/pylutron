import unittest
from unittest.mock import MagicMock, patch, mock_open
from pylutron import Lutron, Output, Keypad, Button, Led, Shade, OccupancyGroup, MotionSensor

class TestFinalCoverage(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron('localhost', 'user', 'pass')
        self.lutron._conn = MagicMock()

    def test_string_representations(self):
        # Output
        output = Output(self.lutron, "Light", 100, "DIMMER", 10, "uuid-1")
        self.assertIn("Light", str(output))
        self.assertIn("DIMMER", repr(output))
        self.assertEqual(output.legacy_uuid, "10-0")

        # Keypad
        keypad = Keypad(self.lutron, "KP", "TYPE", "LOC", 20, "uuid-2")
        self.assertIn("KP", keypad.name)
        self.assertEqual(keypad.type, "TYPE")
        self.assertEqual(keypad.location, "LOC")
        self.assertEqual(keypad.legacy_uuid, "20-0")

        # Button
        button = Button(self.lutron, keypad, "Btn", 1, "T", "D", "uuid-3")
        self.assertIn("Btn", str(button))
        self.assertIn("T", repr(button))
        self.assertEqual(button.button_type, "T")

        # LED
        led = Led(self.lutron, keypad, "LED", 1, 81, "uuid-4")
        self.assertIn("LED", str(led))
        self.assertIn("81", repr(led))
        self.assertEqual(led.last_state, False)

        # OccupancyGroup
        area = MagicMock()
        area.name = "Room"
        area.id = 5
        occ = OccupancyGroup(self.lutron, "100", "uuid-5")
        occ._bind_area(area)
        occ.handle_update(['3', '3']) # Set state to OCCUPIED
        self.assertIn("Room", str(occ))
        self.assertEqual(occ.legacy_uuid, "5-100")
        self.assertEqual(occ.group_number, "100")
        self.assertEqual(occ.name, "Occ Room")
        self.assertIn("area_name", repr(occ))

    def test_lutron_properties(self):
        self.lutron.set_guid("NEW-GUID")
        self.assertEqual(self.lutron.guid, "NEW-GUID")
        self.assertIsNone(self.lutron.name)
        self.assertEqual(len(self.lutron.areas), 0)

    @patch('urllib.request.urlopen')
    @patch('builtins.open', new_callable=mock_open, read_data=b'<Project><GUID>G</GUID><OccupancyGroups/><Areas><Area Name="P" IntegrationID="0"><Areas/></Area></Areas></Project>')
    def test_load_xml_db_from_cache(self, mock_file, mock_url):
        # Test loading from cache
        # Use a fresh Lutron object to avoid ID registration issues
        lutron = Lutron('localhost', 'user', 'pass')
        result = lutron.load_xml_db(cache_path='dummy.xml')
        self.assertTrue(result)
        mock_file.assert_called_with('dummy.xml', 'rb')
        self.assertEqual(lutron.guid, 'G')

    @patch('urllib.request.urlopen')
    def test_load_xml_db_from_repeater(self, mock_url):
        # Mock urlopen return value
        mock_response = MagicMock()
        mock_response.read.return_value = b'<Project><GUID>R</GUID><OccupancyGroups/><Areas><Area Name="P" IntegrationID="0"><Areas/></Area></Areas></Project>'
        mock_response.__enter__.return_value = mock_response
        mock_url.return_value = mock_response

        # Test loading from repeater (no cache)
        lutron = Lutron('localhost', 'user', 'pass')
        result = lutron.load_xml_db()
        self.assertTrue(result)
        mock_url.assert_called()
        self.assertEqual(lutron.guid, 'R')

    def test_output_is_dimmable_edge_cases(self):
        # Test various non-dimmable types
        non_dim_types = ['NON_DIM', 'NON_DIM_INC', 'NON_DIM_ELV', 'EXHAUST_FAN_TYPE', 'RELAY_LIGHTING', 'SWITCHED_MOTOR', 'CCO_SOMETHING']
        for i, t in enumerate(non_dim_types):
            out = Output(self.lutron, "N", 0, t, 1000 + i, "u")
            self.assertFalse(out.is_dimmable, f"Type {t} should not be dimmable")

if __name__ == '__main__':
    unittest.main()
