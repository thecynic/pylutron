import unittest
from pylutron import Lutron, LutronXmlDbParser, Motor, Shade

# Minimal XML for testing
MINIMAL_XML = """
<Lutron>
    <GUID>12345678-ABCD-1234-ABCD-1234567890AB</GUID>
    <OccupancyGroups>
        <OccupancyGroup UUID="OCC-1" OccupancyGroupNumber="1" />
    </OccupancyGroups>
    <Areas>
        <Area Name="Project">
            <Areas>
                <Area Name="Living Room" IntegrationID="1" OccupancyGroupAssignedToID="1">
                    <Outputs>
                        <Output Name="Sconce" IntegrationID="2" OutputType="NON_DIM" Wattage="100" UUID="OUT-1" />
                    </Outputs>
                    <DeviceGroups>
                        <DeviceGroup Name="Wall Keypad">
                             <Devices>
                                 <Device Name="Main" IntegrationID="3" DeviceType="SEETOUCH_KEYPAD" UUID="DEV-1">
                                    <Components>
                                        <Component ComponentNumber="1" ComponentType="BUTTON">
                                            <Button Engraving="On" ButtonType="Toggle" Direction="Press" UUID="BTN-1" />
                                        </Component>
                                    </Components>
                                 </Device>
                             </Devices>
                        </DeviceGroup>
                    </DeviceGroups>
                </Area>
            </Areas>
        </Area>
    </Areas>
</Lutron>
"""

# XML exercising the full parser pipeline for motorized outputs.
# Pattern (nested <Areas><Area>) adapted from @sergiobaiao's test in
# https://github.com/thecynic/pylutron/pull/128
MOTORIZED_OUTPUTS_XML = """
<Lutron>
    <GUID>12345678-ABCD-1234-ABCD-1234567890AB</GUID>
    <Areas>
        <Area Name="Project">
            <Areas>
                <Area Name="Living Room" IntegrationID="1">
                    <Outputs>
                        <Output Name="Curtain Motor" IntegrationID="10" OutputType="MOTOR" Wattage="100" UUID="OUT-MOTOR-1" />
                        <Output Name="Window Shade" IntegrationID="11" OutputType="SYSTEM_SHADE" Wattage="50" UUID="OUT-SHADE-1" />
                        <Output Name="Ceiling Light" IntegrationID="12" OutputType="AUTO_DETECT" Wattage="75" UUID="OUT-DIM-1" />
                    </Outputs>
                </Area>
            </Areas>
        </Area>
    </Areas>
</Lutron>
"""


class TestLutronXmlDbParser(unittest.TestCase):
    def setUp(self) -> None:
        self.lutron = Lutron('localhost', 'user', 'pass')

    def test_parse_simple_xml(self) -> None:
        parser = LutronXmlDbParser(self.lutron, MINIMAL_XML)
        self.assertTrue(parser.parse())
        
        # Check Project Info
        # GUID is set on the lutron object
        self.assertEqual(self.lutron.guid, '12345678-ABCD-1234-ABCD-1234567890AB')
        # Name and areas are stored in the parser until loaded
        self.assertEqual(parser.project_name, 'Project')
        
        # Check Areas
        self.assertEqual(len(parser.areas), 1)
        area = parser.areas[0]
        self.assertEqual(area.name, 'Living Room')
        self.assertEqual(area.id, 1)

    def test_parse_outputs(self) -> None:
        parser = LutronXmlDbParser(self.lutron, MINIMAL_XML)
        parser.parse()
        area = parser.areas[0]
        
        self.assertEqual(len(area.outputs), 1)
        output = area.outputs[0]
        self.assertEqual(output.name, 'Sconce')
        self.assertEqual(output.watts, 100)
        self.assertEqual(output.type, 'NON_DIM')
        self.assertEqual(output.id, 2)

    def test_parse_motor_output_as_motor(self) -> None:
        parser = LutronXmlDbParser(self.lutron, MOTORIZED_OUTPUTS_XML)
        self.assertTrue(parser.parse())
        area = parser.areas[0]

        outputs_by_id = {o.id: o for o in area.outputs}
        motor = outputs_by_id[10]
        self.assertIsInstance(motor, Motor)
        self.assertEqual(motor.name, 'Curtain Motor')
        self.assertEqual(motor.type, 'MOTOR')
        self.assertEqual(motor.watts, 100)
        self.assertFalse(motor.is_dimmable)

    def test_parse_system_shade_output_as_shade_not_motor(self) -> None:
        parser = LutronXmlDbParser(self.lutron, MOTORIZED_OUTPUTS_XML)
        parser.parse()
        area = parser.areas[0]

        outputs_by_id = {o.id: o for o in area.outputs}
        shade = outputs_by_id[11]
        self.assertIsInstance(shade, Shade)
        self.assertNotIsInstance(shade, Motor)
        self.assertEqual(shade.type, 'SYSTEM_SHADE')

    def test_parse_mixed_outputs_preserves_non_motorized(self) -> None:
        parser = LutronXmlDbParser(self.lutron, MOTORIZED_OUTPUTS_XML)
        parser.parse()
        area = parser.areas[0]

        self.assertEqual(len(area.outputs), 3)
        outputs_by_id = {o.id: o for o in area.outputs}
        dimmer = outputs_by_id[12]
        self.assertNotIsInstance(dimmer, Shade)
        self.assertNotIsInstance(dimmer, Motor)
        self.assertEqual(dimmer.type, 'AUTO_DETECT')

    def test_parse_keypad(self) -> None:
        parser = LutronXmlDbParser(self.lutron, MINIMAL_XML)
        parser.parse()
        area = parser.areas[0]
        
        self.assertEqual(len(area.keypads), 1)
        keypad = area.keypads[0]
        self.assertEqual(keypad.name, 'Main')
        self.assertEqual(keypad.location, 'Wall Keypad')
        
        # Check Buttons
        self.assertEqual(len(keypad.buttons), 1)
        button = keypad.buttons[0]
        self.assertEqual(button.name, 'On')
        self.assertEqual(button.number, 1)

if __name__ == '__main__':
    unittest.main()
