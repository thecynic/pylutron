import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, Output, _RequestHelper

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

    def test_query_is_reissued_after_a_timed_out_wait(self) -> None:
        """A query whose reply never arrives must not wedge the object.

        request() only performs the action when its wait queue is empty, and
        callers wait with a timeout. A caller that gave up used to leave its
        event behind, so the queue never emptied again and no further query was
        ever sent -- the output stopped talking to the controller for good.
        """
        send = cast(MagicMock, self.lutron._conn.send)
        _ = self.output.level  # no reply arrives, wait times out
        _ = self.output.level  # must ask again rather than give up silently
        self.assertEqual(send.call_count, 2)
        send.assert_called_with('?OUTPUT,1,1')

    def test_request_helper_cancel(self) -> None:
        calls = []
        helper = _RequestHelper()
        ev1 = helper.request(lambda: calls.append(1))
        # A second request while one is pending is still coalesced.
        ev2 = helper.request(lambda: calls.append(2))
        self.assertEqual(calls, [1])
        helper.cancel(ev1)
        helper.cancel(ev2)
        # With both waiters gone the next request performs the action again.
        helper.request(lambda: calls.append(3))
        self.assertEqual(calls, [1, 3])
        # Cancelling an event that notify() already cleared is a no-op.
        helper.notify()
        helper.cancel(ev1)


if __name__ == '__main__':
    unittest.main()
