import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, Shade, MotorLoad

from typing import Any, cast

class TestShade(unittest.TestCase):
    def setUp(self) -> None:
        self.lutron = Lutron("1.1.1.1", "user", "pass")
        self.lutron._conn = MagicMock()
        # Mock register_id to avoid errors
        self.lutron.register_id = MagicMock() # type: ignore[method-assign]

    def test_shade_commands(self) -> None:
        # Create a shade (Output with type SYSTEM_SHADE)
        shade = Shade(self.lutron, "Master Shade", 100, "SYSTEM_SHADE", 50, "uuid-shade")
        
        # Test start_raise
        shade.start_raise()
        # Expect OP_EXECUTE, Output._CMD_TYPE, integration_id, Shade._ACTION_RAISE
        # #OUTPUT,50,2
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#OUTPUT,50,2')
        
        # Test start_lower
        shade.start_lower()
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#OUTPUT,50,3')
        
        # Test stop
        shade.stop()
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#OUTPUT,50,4')

    def test_motor_load_commands(self) -> None:
        motor = MotorLoad(self.lutron, "Master Motor", 100, "MOTOR", 51, "uuid-motor")

        motor.open()
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#OUTPUT,51,2')

        motor.close()
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#OUTPUT,51,3')

        motor.stop()
        cast(MagicMock, self.lutron._conn.send).assert_called_with('#OUTPUT,51,4')

    def test_motor_load_rejects_level_commands(self) -> None:
        motor = MotorLoad(self.lutron, "Master Motor", 100, "MOTOR", 51, "uuid-motor")

        with self.assertRaises(ValueError):
            motor.set_level(100)

        with self.assertRaises(ValueError):
            motor.level = 0
