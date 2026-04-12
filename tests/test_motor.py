import unittest
from unittest.mock import MagicMock
from xml.etree import ElementTree as ET

from pylutron import Lutron, LutronXmlDbParser, Motor, Output, Shade

from typing import cast


class TestMotor(unittest.TestCase):
    """Tests for the Motor output entity.

    Motors share the raise/lower/stop wire protocol with shades but do not
    honor the OUTPUT set-level action in practice, even though the Lutron
    integration protocol documentation claims they do. These tests pin both
    the shared behavior (raise/lower/stop) and the motor-specific divergence
    (set_level raises, is_dimmable is False).
    """

    def setUp(self) -> None:
        self.lutron = Lutron("1.1.1.1", "user", "pass")
        self.lutron._conn = MagicMock()
        self.lutron.register_id = MagicMock()  # type: ignore[method-assign]
        self.motor = Motor(self.lutron, "Drapery Motor", 0, "MOTOR", 42, "uuid-motor")
        self.send = cast(MagicMock, self.lutron._conn.send)

    def test_start_raise_emits_action_2(self) -> None:
        self.motor.start_raise()
        self.send.assert_called_with('#OUTPUT,42,2')

    def test_start_lower_emits_action_3(self) -> None:
        self.motor.start_lower()
        self.send.assert_called_with('#OUTPUT,42,3')

    def test_stop_emits_action_4(self) -> None:
        self.motor.stop()
        self.send.assert_called_with('#OUTPUT,42,4')

    def test_set_level_raises_attribute_error(self) -> None:
        with self.assertRaises(AttributeError):
            self.motor.set_level(50.0)
        self.send.assert_not_called()

    def test_level_property_setter_raises_attribute_error(self) -> None:
        with self.assertRaises(AttributeError):
            self.motor.level = 50.0
        self.send.assert_not_called()

    def test_set_level_raises_at_boundaries(self) -> None:
        for boundary in (0.0, 100.0):
            with self.assertRaises(AttributeError):
                self.motor.set_level(boundary)
        self.send.assert_not_called()

    def test_motor_is_not_dimmable(self) -> None:
        self.assertFalse(self.motor.is_dimmable)

    def test_raise_lower_do_not_touch_cached_level(self) -> None:
        """Consistent with Shade: raise/lower/stop don't update last_level.

        The repeater is the source of truth and pushes level updates
        asynchronously as the motor travels.
        """
        self.motor._level = 37.5
        self.motor.start_raise()
        self.assertEqual(self.motor.last_level(), 37.5)
        self.motor.start_lower()
        self.assertEqual(self.motor.last_level(), 37.5)
        self.motor.stop()
        self.assertEqual(self.motor.last_level(), 37.5)

    def test_handle_update_still_tracks_level(self) -> None:
        """Motors report position as they travel; inbound updates must work."""
        handled = self.motor.handle_update(['1', '42.00'])
        self.assertTrue(handled)
        self.assertEqual(self.motor.last_level(), 42.0)


class TestMotorParser(unittest.TestCase):
    """Ensures the XML parser routes OutputType correctly."""

    def setUp(self) -> None:
        self.lutron = Lutron("1.1.1.1", "user", "pass")
        self.lutron._conn = MagicMock()
        self.lutron.register_id = MagicMock()  # type: ignore[method-assign]
        self.parser = LutronXmlDbParser(self.lutron, b"")

    def _output_xml(self, output_type: str) -> ET.Element:
        return ET.fromstring(
            '<Output Name="Test" Wattage="0" IntegrationID="7" '
            f'OutputType="{output_type}" UUID="uuid-test"/>'
        )

    def test_motor_output_type_creates_motor(self) -> None:
        result = self.parser._parse_output(self._output_xml("MOTOR"))
        self.assertIsInstance(result, Motor)

    def test_system_shade_output_type_creates_shade_not_motor(self) -> None:
        result = self.parser._parse_output(self._output_xml("SYSTEM_SHADE"))
        self.assertIsInstance(result, Shade)
        self.assertNotIsInstance(result, Motor)

    def test_dimmer_output_type_creates_plain_output(self) -> None:
        result = self.parser._parse_output(self._output_xml("AUTO_DETECT"))
        self.assertIs(type(result), Output)


if __name__ == '__main__':
    unittest.main()
