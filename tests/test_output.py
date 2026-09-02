import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, Output

from typing import cast

class TestOutput(unittest.TestCase):
    def setUp(self) -> None:
        self.lutron = Lutron('localhost', 'user', 'pass')
        self.lutron._conn.send = MagicMock() # type: ignore[method-assign]
        self.output = Output(self.lutron, "Ceiling Light", 100, "DIMMER", 1, "601")

    def test_properties(self) -> None:
        self.assertEqual(self.output.name, "Ceiling Light")
        self.assertEqual(self.output.watts, 100)
        self.assertEqual(self.output.type, "DIMMER")
        self.assertEqual(self.output.id, 1)

    def test_is_dimmable(self) -> None:
        # DIMMER should be dimmable
        self.assertTrue(self.output.is_dimmable)
        
        # NON_DIM should not be dimmable
        non_dim = Output(self.lutron, "Fan", 100, "NON_DIM", 2, "602")
        self.assertFalse(non_dim.is_dimmable)

    def test_set_level_executes_command(self) -> None:
        self.output.level = 50.0
        # Verify that setting the level sends the correct command without fade time
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#OUTPUT,1,1,50.00')
        self.assertEqual(self.output.last_level(), 50.0)

    def test_handle_update(self) -> None:
        # Simulate receiving an update from the controller
        # Action 1 (ZONE_LEVEL), Level 75.00
        handled = self.output.handle_update(['1', '75.00'])
        self.assertTrue(handled)
        self.assertEqual(self.output.last_level(), 75.0)

    def test_set_level_is_not_suppressed_by_a_stale_cache(self) -> None:
        """Setting the level must always send, even if the cache agrees.

        The cached level is only as good as the last report from the
        controller. It goes stale whenever a report is lost, and on systems
        that do not send unsolicited reports for a given change it is stale by
        construction. Suppressing the command then leaves the caller with no
        way to reassert a level: the first request appears to work, every
        identical one after it is silently dropped.
        """
        send = cast(MagicMock, self.lutron._conn.send)
        self.output.set_level(50.0)
        self.output.set_level(50.0)
        self.assertEqual(send.call_count, 2)

    def test_set_level_honours_a_new_fade_time(self) -> None:
        """Same level, different fade, is a different command."""
        send = cast(MagicMock, self.lutron._conn.send)
        self.output.set_level(50.0)
        self.output.set_level(50.0, fade_time_seconds=4)
        send.assert_called_with('#OUTPUT,1,1,50.00,0:00:04')


if __name__ == '__main__':
    unittest.main()
