import unittest
from unittest.mock import MagicMock
from pylutron import Lutron, LutronXmlDbParser

class TestParserEdgeCases(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron('localhost', 'user', 'pass')

    def test_unknown_device_type(self):
        xml = """
        <Lutron>
            <GUID>GUID</GUID>
            <OccupancyGroups />
            <Areas>
                <Area Name="Project">
                    <Areas>
                        <Area Name="Room1" IntegrationID="1">
                            <DeviceGroups>
                                <DeviceGroup Name="Loc">
                                    <Devices>
                                        <Device Name="UnknownThing" DeviceType="ALIEN_TECH" IntegrationID="10" UUID="D1" />
                                    </Devices>
                                </DeviceGroup>
                            </DeviceGroups>
                        </Area>
                    </Areas>
                </Area>
            </Areas>
        </Lutron>
        """
        parser = LutronXmlDbParser(self.lutron, xml)
        self.assertTrue(parser.parse())
        # The alien device should be ignored, so no keypads in the area
        self.assertEqual(len(parser.areas[0].keypads), 0)

    def test_device_defined_directly_in_group_tag(self):
        # Coverage for: elif device_group.tag == 'Device': devs = [device_group]
        xml = """
        <Lutron>
            <GUID>GUID</GUID>
            <OccupancyGroups />
            <Areas>
                <Area Name="Project">
                    <Areas>
                        <Area Name="Room1" IntegrationID="1">
                            <DeviceGroups>
                                <Device Name="DirectKeypad" DeviceType="SEETOUCH_KEYPAD" IntegrationID="11" UUID="D2">
                                    <Components />
                                </Device>
                            </DeviceGroups>
                        </Area>
                    </Areas>
                </Area>
            </Areas>
        </Lutron>
        """
        parser = LutronXmlDbParser(self.lutron, xml)
        self.assertTrue(parser.parse())
        self.assertEqual(len(parser.areas[0].keypads), 1)
        self.assertEqual(parser.areas[0].keypads[0].name, "DirectKeypad")

    def test_missing_occupancy_group(self):
        # Coverage for: if not occupancy_group: _LOGGER.warning...
        xml = """
        <Lutron>
            <GUID>GUID</GUID>
            <OccupancyGroups /> <!-- Empty -->
            <Areas>
                <Area Name="Project">
                    <Areas>
                        <Area Name="Room1" IntegrationID="1" OccupancyGroupAssignedToID="999" />
                    </Areas>
                </Area>
            </Areas>
        </Lutron>
        """
        parser = LutronXmlDbParser(self.lutron, xml)
        # Should not raise
        self.assertTrue(parser.parse())
        area = parser.areas[0]
        # occupancy_group should be None
        self.assertIsNone(area.occupancy_group)

    def test_keypad_components_edge_cases(self):
        # Coverage for: unknown component type, no components
        xml = """
        <Lutron>
            <GUID>GUID</GUID>
            <OccupancyGroups />
            <Areas>
                <Area Name="Project">
                    <Areas>
                        <Area Name="Room1" IntegrationID="1">
                            <DeviceGroups>
                                <DeviceGroup Name="Loc">
                                    <Devices>
                                        <Device Name="Keypad" IntegrationID="20" DeviceType="SEETOUCH_KEYPAD" UUID="K1">
                                            <Components>
                                                <!-- Valid Button -->
                                                <Component ComponentNumber="1" ComponentType="BUTTON">
                                                    <Button Engraving="Btn" ButtonType="Toggle" Direction="Press" />
                                                </Component>
                                                <!-- Unknown Component Type -->
                                                <Component ComponentNumber="2" ComponentType="FLUX_CAPACITOR" />
                                                <!-- Not a Component tag (unlikely valid XML but parser checks tag) -->
                                                <SomethingElse />
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
        parser = LutronXmlDbParser(self.lutron, xml)
        self.assertTrue(parser.parse())
        keypad = parser.areas[0].keypads[0]
        # Should have 1 button, ignoring the others
        self.assertEqual(len(keypad.buttons), 1)

    def test_button_with_no_name(self):
        # Coverage for: if not name: name = "Unknown Button"
        xml = """
        <Lutron>
            <GUID>GUID</GUID>
            <OccupancyGroups />
            <Areas>
                <Area Name="Project">
                    <Areas>
                        <Area Name="Room1" IntegrationID="1">
                            <DeviceGroups>
                                <DeviceGroup Name="Loc">
                                    <Devices>
                                        <Device Name="Keypad" IntegrationID="30" DeviceType="SEETOUCH_KEYPAD" UUID="K2">
                                            <Components>
                                                <Component ComponentNumber="1" ComponentType="BUTTON">
                                                    <!-- Empty engraving -->
                                                    <Button Engraving="" ButtonType="Toggle" Direction="Press" />
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
        parser = LutronXmlDbParser(self.lutron, xml)
        self.assertTrue(parser.parse())
        button = parser.areas[0].keypads[0].buttons[0]
        self.assertEqual(button.name, "Unknown Button")

    def test_unknown_device_group_child_tag(self):
        # Coverage for: else: _LOGGER.info("Unknown tag in DeviceGroups child %s" % devs)
        xml = """
        <Lutron>
            <GUID>GUID</GUID>
            <OccupancyGroups />
            <Areas>
                <Area Name="Project">
                    <Areas>
                        <Area Name="Room1" IntegrationID="1">
                            <DeviceGroups>
                                <RandomTag />
                            </DeviceGroups>
                        </Area>
                    </Areas>
                </Area>
            </Areas>
        </Lutron>
        """
        parser = LutronXmlDbParser(self.lutron, xml)
        # Should assume empty devs and continue
        self.assertTrue(parser.parse())
        self.assertEqual(len(parser.areas[0].keypads), 0)

if __name__ == '__main__':
    unittest.main()
