import unittest
from pylutron import Lutron, LutronXmlDbParser

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

class TestLutronXmlDbParser(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron('localhost', 'user', 'pass')

    def test_parse_simple_xml(self):
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

    def test_parse_outputs(self):
        parser = LutronXmlDbParser(self.lutron, MINIMAL_XML)
        parser.parse()
        area = parser.areas[0]
        
        self.assertEqual(len(area.outputs), 1)
        output = area.outputs[0]
        self.assertEqual(output.name, 'Sconce')
        self.assertEqual(output.watts, 100)
        self.assertEqual(output.type, 'NON_DIM')
        self.assertEqual(output.id, 2)

    def test_parse_keypad(self):
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
