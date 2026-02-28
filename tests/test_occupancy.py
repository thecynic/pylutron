import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, OccupancyGroup, MotionSensor

class TestOccupancy(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron("1.1.1.1", "user", "pass")
        self.lutron._conn = MagicMock()
        self.lutron.register_id = MagicMock()

    def test_occupancy_group_state(self):
        # Occupancy Group 100
        occ_group = OccupancyGroup(self.lutron, 100, "uuid-occ")
        
        # Test handle_update for occupancy change
        # Action is 3 (_ACTION_STATE)
        # Params: 3 (OCCUPIED), 4 (VACANT), 255 (UNKNOWN)
        
        # Test Occupied
        occ_group.handle_update(['3', '3']) # Action 3, State 3 (Occupied)
        self.assertEqual(occ_group.state, OccupancyGroup.State.OCCUPIED)
        
        # Test Vacant
        occ_group.handle_update(['3', '4'])
        self.assertEqual(occ_group.state, OccupancyGroup.State.VACANT)
        
    def test_motion_sensor_battery(self):
        sensor = MotionSensor(self.lutron, "Sensor 1", 500, "uuid-sensor")
        
        # MotionSensor battery query
        sensor._do_query_battery()
        
        # Verify that the query command is sent correctly
        self.assertEqual(self.lutron._conn.send.call_count, 1)
        args = self.lutron._conn.send.call_args[0][0]
        self.assertTrue(args.startswith('?DEVICE,500'))

    def test_occupancy_event(self):
        occ_group = OccupancyGroup(self.lutron, 100, "uuid-occ")
        handler = MagicMock()
        occ_group.subscribe(handler, None)
        
        # Trigger update
        occ_group.handle_update(['3', '3']) # Occupied
        
        self.assertTrue(handler.called)
        call_args = handler.call_args
        self.assertEqual(call_args[0][0], occ_group)
        self.assertEqual(call_args[0][2], OccupancyGroup.Event.OCCUPANCY)
        self.assertEqual(call_args[0][3]['state'], OccupancyGroup.State.OCCUPIED)
