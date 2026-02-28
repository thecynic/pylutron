import unittest
from pylutron import Lutron, LutronXmlDbParser

# Anonymized and truncated version of the provided DbXmlInfo.xml
COMPLEX_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<Project>
    <ProjectName ProjectName="Test House" UUID="1" />
    <GUID>7ccee645777f46459a3d5216b6e54d5a</GUID>
    <Areas>
        <Area Name="House" UUID="3" IntegrationID="0" OccupancyGroupAssignedToID="0" SortOrder="0">
            <Areas>
                <Area Name="Living Room" UUID="377" IntegrationID="13" OccupancyGroupAssignedToID="379" SortOrder="14">
                    <DeviceGroups>
                        <DeviceGroup Name="Front Door" SortOrder="0">
                            <Devices>
                                <Device Name="Keypad" UUID="7589" SerialNumber="12345678" IntegrationID="40" DeviceType="HYBRID_SEETOUCH_KEYPAD" GangPosition="0" SortOrder="0">
                                    <Components>
                                        <Component ComponentNumber="1" ComponentType="BUTTON">
                                            <Button Name="Button 1" UUID="7603" Engraving="Loft" ButtonType="Toggle" />
                                        </Component>
                                        <Component ComponentNumber="18" ComponentType="BUTTON">
                                            <Button Name="Button 18" UUID="7621" ButtonType="MasterRaiseLower" Direction="Lower" />
                                        </Component>
                                        <Component ComponentNumber="81" ComponentType="LED">
                                            <LED UUID="7596" />
                                        </Component>
                                    </Components>
                                </Device>
                            </Devices>
                        </DeviceGroup>
                    </DeviceGroups>
                    <Outputs>
                        <Output Name="Ceiling Lights" UUID="1412" IntegrationID="52" OutputType="MLV" Wattage="0" />
                    </Outputs>
                </Area>
                <Area Name="Crawl Space" UUID="77" IntegrationID="4" OccupancyGroupAssignedToID="79" SortOrder="2">
                    <DeviceGroups>
                        <Device Name="Main Repeater" UUID="88" SerialNumber="22229148" IntegrationID="1" DeviceType="MAIN_REPEATER" GangPosition="0" SortOrder="805349400">
                            <Components>
                                <Component ComponentNumber="1" ComponentType="BUTTON">
                                    <Button Name="Button 1" UUID="194" ButtonType="Toggle" />
                                </Component>
                                <Component ComponentNumber="101" ComponentType="LED">
                                    <LED UUID="93" />
                                </Component>
                            </Components>
                        </Device>
                    </DeviceGroups>
                </Area>
                <Area Name="Her Closet" UUID="337" IntegrationID="9" OccupancyGroupAssignedToID="339" SortOrder="10">
                    <Outputs>
                        <Output Name="Light" UUID="1688" IntegrationID="63" OutputType="ELV" Wattage="0" />
                    </Outputs>
                </Area>
                <Area Name="Child Room" UUID="437" IntegrationID="19" OccupancyGroupAssignedToID="439">
                    <DeviceGroups>
                        <DeviceGroup Name="Door">
                            <Devices>
                                <Device Name="Pico Remote" UUID="7063" IntegrationID="48" DeviceType="PICO_KEYPAD">
                                    <Components>
                                        <Component ComponentNumber="2" ComponentType="BUTTON">
                                            <Button Name="Button 1" UUID="7066" Engraving="On" ButtonType="SingleAction" />
                                        </Component>
                                        <Component ComponentNumber="5" ComponentType="BUTTON">
                                            <Button Name="Button 4" UUID="7075" Engraving="Raise" ButtonType="SingleSceneRaiseLower" Direction="Raise" />
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
    <OccupancyGroups>
        <OccupancyGroup UUID="339" OccupancyGroupNumber="339" ButtonType="DualAction" />
        <OccupancyGroup UUID="379" OccupancyGroupNumber="379" />
        <OccupancyGroup UUID="79" OccupancyGroupNumber="79" />
        <OccupancyGroup UUID="439" OccupancyGroupNumber="439" />
    </OccupancyGroups>
</Project>
"""

class TestComplexXml(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron('localhost', 'user', 'pass')
        self.parser = LutronXmlDbParser(self.lutron, COMPLEX_XML)
        self.assertTrue(self.parser.parse())

    def test_main_repeater_parsing(self):
        # Find Main Repeater
        # It's in 'Crawl Space'
        crawl_space = next(a for a in self.parser.areas if a.name == 'Crawl Space')
        main_repeater = crawl_space.keypads[0]
        self.assertEqual(main_repeater.type, 'MAIN_REPEATER')
        self.assertEqual(main_repeater.name, 'Main Repeater')
        
        # Check components
        # LED on Main Repeater has base 100 (so component 101 -> LED 1)
        led_1 = next(l for l in main_repeater.leds if l.component_number == 101)
        self.assertEqual(led_1.number, 1) # 101 - 100

    def test_hybrid_keypad_parsing(self):
        living_room = next(a for a in self.parser.areas if a.name == 'Living Room')
        keypad = living_room.keypads[0]
        self.assertEqual(keypad.type, 'HYBRID_SEETOUCH_KEYPAD')
        
        # Check MasterRaiseLower button
        btn_18 = next(b for b in keypad.buttons if b.component_number == 18)
        self.assertEqual(btn_18.button_type, 'MasterRaiseLower')
        self.assertEqual(btn_18.name, 'Dimmer Lower') # Should be auto-generated name

    def test_pico_remote_parsing(self):
        child_room = next(a for a in self.parser.areas if a.name == 'Child Room')
        pico = child_room.keypads[0]
        self.assertEqual(pico.type, 'PICO_KEYPAD')
        
        # Check SingleSceneRaiseLower
        # The parser prepends "Dimmer " for these types
        btn_raise = next(b for b in pico.buttons if b.name == 'Dimmer Raise')
        self.assertEqual(btn_raise.button_type, 'SingleSceneRaiseLower')

    def test_occupancy_group_linking(self):
        her_closet = next(a for a in self.parser.areas if a.name == 'Her Closet')
        self.assertIsNotNone(her_closet.occupancy_group)
        self.assertEqual(her_closet.occupancy_group.group_number, '339')

if __name__ == '__main__':
    unittest.main()
