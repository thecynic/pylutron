import unittest
from pylutron import Lutron, LutronXmlDbParser, Motor, Shade

# Minimal XML for testing
MINIMAL_XML = """
<Lutron>
    <GUID>12345678-ABCD-1234-ABCD-1234567890AB</GUID>
    <OccupancyGroups>
        <OccupancyGroup UUID="100" OccupancyGroupNumber="1" />
    </OccupancyGroups>
    <Areas>
        <Area Name="Project">
            <Areas>
                <Area Name="Living Room" IntegrationID="1" OccupancyGroupAssignedToID="1">
                    <Outputs>
                        <Output Name="Sconce" IntegrationID="2" OutputType="NON_DIM" Wattage="100" UUID="501" />
                    </Outputs>
                    <DeviceGroups>
                        <DeviceGroup Name="Wall Keypad">
                             <Devices>
                                 <Device Name="Main" IntegrationID="3" DeviceType="SEETOUCH_KEYPAD" UUID="502">
                                    <Components>
                                        <Component ComponentNumber="1" ComponentType="BUTTON">
                                            <Button Engraving="On" ButtonType="Toggle" Direction="Press" UUID="503" />
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
                        <Output Name="Cortina" IntegrationID="10" OutputType="MOTOR" Wattage="0" UUID="1954" />
                        <Output Name="Window Shade" IntegrationID="11" OutputType="SYSTEM_SHADE" Wattage="0" UUID="2001" />
                        <!-- Non-motorized output to verify it isn't misrouted to Shade/Motor -->
                        <Output Name="LEDs" IntegrationID="12" OutputType="INC" Wattage="40" UUID="714" />
                    </Outputs>
                </Area>
            </Areas>
        </Area>
    </Areas>
</Lutron>
"""


# A button driving outputs directly (GOTO_LEVEL) next to one going through a
# scene owned by a *different* area (GOTO_SCENE). That split is the common
# shape in HomeWorks QS projects: wall keypads sit in their own area and recall
# scenes belonging to the rooms they control.
BUTTON_PROGRAMMING_XML = """
<Lutron>
    <GUID>12345678-ABCD-1234-ABCD-1234567890AB</GUID>
    <Areas>
        <Area Name="Project">
            <Areas>
                <Area Name="Living Room" IntegrationID="1">
                    <Scenes>
                        <Scene Number="3" Name="Evening">
                            <Presets>
                                <Preset UUID="900">
                                    <PresetAssignments>
                                        <PresetAssignment AssignmentName="GOTO_LEVEL" AssignmentType="2">
                                            <Level>40.00</Level><IntegrationID>10</IntegrationID>
                                        </PresetAssignment>
                                        <PresetAssignment AssignmentName="GOTO_LEVEL" AssignmentType="2">
                                            <Level>0.00</Level><IntegrationID>11</IntegrationID>
                                        </PresetAssignment>
                                    </PresetAssignments>
                                </Preset>
                            </Presets>
                        </Scene>
                    </Scenes>
                    <Outputs>
                        <Output Name="Downlights" IntegrationID="10" OutputType="DALI" Wattage="0" UUID="601" />
                        <Output Name="Cove" IntegrationID="11" OutputType="DALI" Wattage="0" UUID="602" />
                        <Output Name="Lamp" IntegrationID="12" OutputType="DALI" Wattage="0" UUID="603" />
                    </Outputs>
                </Area>
                <Area Name="Hall" IntegrationID="2">
                    <DeviceGroups>
                        <DeviceGroup Name="Wall Keypad">
                            <Devices>
                                <Device Name="Entry" IntegrationID="20" DeviceType="SEETOUCH_KEYPAD" UUID="700">
                                    <Components>
                                        <Component ComponentNumber="1" ComponentType="BUTTON">
                                            <Button Engraving="Evening" ButtonType="SingleAction" UUID="701">
                                                <Actions><Action Name="Press" ActionType="3"><Presets>
                                                    <Preset Name="Press On" UUID="702"><PresetAssignments>
                                                        <PresetAssignment AssignmentName="GOTO_SCENE" AssignmentType="5">
                                                            <Number>3</Number><IntegrationID>1</IntegrationID>
                                                        </PresetAssignment>
                                                    </PresetAssignments></Preset>
                                                </Presets></Action></Actions>
                                            </Button>
                                        </Component>
                                        <Component ComponentNumber="2" ComponentType="BUTTON">
                                            <Button Engraving="Lamp" ButtonType="SingleAction" UUID="703">
                                                <Actions><Action Name="Press" ActionType="3"><Presets>
                                                    <Preset Name="Press On" UUID="704"><PresetAssignments>
                                                        <PresetAssignment AssignmentName="GOTO_LEVEL" AssignmentType="2">
                                                            <Level>75.00</Level><IntegrationID>12</IntegrationID>
                                                        </PresetAssignment>
                                                    </PresetAssignments></Preset>
                                                </Presets></Action></Actions>
                                            </Button>
                                        </Component>
                                        <Component ComponentNumber="3" ComponentType="BUTTON">
                                            <Button Engraving="Unprogrammed" ButtonType="SingleAction" UUID="705" />
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
        self.assertEqual(motor.name, 'Cortina')
        self.assertEqual(motor.type, 'MOTOR')
        self.assertEqual(motor.watts, 0)
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
        self.assertEqual(dimmer.type, 'INC')
        self.assertEqual(dimmer.watts, 40)

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


class TestButtonAffectedOutputs(unittest.TestCase):
    """Buttons expose which outputs their programming can change."""

    def setUp(self) -> None:
        self.lutron = Lutron("1.1.1.1", "user", "pass")
        parser = LutronXmlDbParser(self.lutron, BUTTON_PROGRAMMING_XML)
        self.assertTrue(parser.parse())
        self.buttons = {
            b.name: b
            for area in parser.areas for kp in area.keypads for b in kp.buttons
        }

    def test_scene_reference_is_resolved_across_areas(self) -> None:
        # The scene belongs to "Living Room"; the keypad sits in "Hall".
        self.assertEqual(self.buttons["Evening"].affected_outputs,
                         {10: 40.0, 11: 0.0})

    def test_direct_level_assignment(self) -> None:
        self.assertEqual(self.buttons["Lamp"].affected_outputs, {12: 75.0})

    def test_button_without_programming(self) -> None:
        self.assertEqual(self.buttons["Unprogrammed"].affected_outputs, {})

    def test_returned_mapping_is_a_copy(self) -> None:
        button = self.buttons["Lamp"]
        button.affected_outputs[12] = 0.0
        self.assertEqual(button.affected_outputs, {12: 75.0})
