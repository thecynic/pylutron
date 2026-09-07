import unittest
from unittest.mock import MagicMock

from pylutron import Lutron, LutronXmlDbParser, Motor, Output, Shade

from typing import cast

OUTPUTS_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<Project>
    <ProjectName ProjectName="Test House" UUID="1" />
    <GUID>7ccee645777f46459a3d5216b6e54d5a</GUID>
    <Areas>
        <Area Name="House" UUID="3" IntegrationID="0" OccupancyGroupAssignedToID="0" SortOrder="0">
            <Areas>
                <Area Name="Sun Room" UUID="10" IntegrationID="5" OccupancyGroupAssignedToID="0" SortOrder="0">
                    <Outputs>
                        <Output Name="QS Shade" UUID="101" IntegrationID="201" OutputType="SYSTEM_SHADE" Wattage="0" />
                        <Output Name="QED Shade" UUID="102" IntegrationID="202" OutputType="SIVOIA_QED" Wattage="0" />
                        <Output Name="Drapes" UUID="103" IntegrationID="203" OutputType="MOTOR" Wattage="0" />
                        <Output Name="Lamp" UUID="104" IntegrationID="204" OutputType="INC" Wattage="60" />
                    </Outputs>
                </Area>
            </Areas>
        </Area>
    </Areas>
</Project>
"""


class TestOutputParsing(unittest.TestCase):
    """The parser instantiates the output class that matches the OutputType."""

    def setUp(self) -> None:
        self.lutron = Lutron('localhost', 'user', 'pass')
        parser = LutronXmlDbParser(self.lutron, OUTPUTS_XML)
        self.assertTrue(parser.parse())
        area = next(a for a in parser.areas if a.name == 'Sun Room')
        self.outputs = {o.name: o for o in area.outputs}
        self.lutron._conn.send = MagicMock()  # type: ignore[method-assign]
        self.send = cast(MagicMock, self.lutron._conn.send)

    def test_system_shade_is_shade(self) -> None:
        shade = self.outputs['QS Shade']
        self.assertIsInstance(shade, Shade)
        self.assertEqual(shade.type, 'SYSTEM_SHADE')

    def test_sivoia_qed_is_shade(self) -> None:
        shade = self.outputs['QED Shade']
        self.assertIsInstance(shade, Shade)
        self.assertNotIsInstance(shade, Motor)
        self.assertEqual(shade.type, 'SIVOIA_QED')
        self.assertEqual(shade.id, 202)

    def test_sivoia_qed_shade_supports_level_and_motion(self) -> None:
        shade = cast(Shade, self.outputs['QED Shade'])
        shade.start_raise()
        self.send.assert_called_with('#OUTPUT,202,2')
        shade.stop()
        self.send.assert_called_with('#OUTPUT,202,4')
        shade.level = 50.0
        self.assertTrue(self.send.call_args[0][0].startswith('#OUTPUT,202,1,'))

    def test_motor_is_motor(self) -> None:
        motor = self.outputs['Drapes']
        self.assertIsInstance(motor, Motor)
        self.assertNotIsInstance(motor, Shade)

    def test_other_outputs_stay_plain(self) -> None:
        lamp = self.outputs['Lamp']
        self.assertIs(type(lamp), Output)
        self.assertTrue(lamp.is_dimmable)


if __name__ == '__main__':
    unittest.main()
