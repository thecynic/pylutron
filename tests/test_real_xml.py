import unittest
from pylutron import Lutron, LutronXmlDbParser

# Sanitized version of the provided real-world XML
REAL_WORLD_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<Project>
    <ProjectName ProjectName="Test Project" UUID="1" />
    <Dealer AccountNumber="TestDealer" UserID="user@example.com" />
    <DealerInformation Name="Test Dealer" Email="user@example.com" Cell="555-555-5555" Phone="555-555-5555" />
    <Latitude>0.0</Latitude>
    <Longitude>0.0</Longitude>
    <GUID>7ccee645777f46459a3d5216b6e54d5a</GUID>
    <Areas>
        <Area Name="Test Project" UUID="3" IntegrationID="0" OccupancyGroupAssignedToID="0" SortOrder="0">
            <Areas>
                <Area Name="Bathroom" UUID="10013" IntegrationID="92" OccupancyGroupAssignedToID="10015" SortOrder="19">
                    <Outputs>
                        <Output Name="Light" UUID="1641" IntegrationID="61" OutputType="MLV" Wattage="0" SortOrder="0" />
                        <Output Name="Fan" UUID="1620" IntegrationID="60" OutputType="NON_DIM" Wattage="0" SortOrder="1" />
                    </Outputs>
                </Area>
                <Area Name="Hallway" UUID="477" IntegrationID="23" OccupancyGroupAssignedToID="479" SortOrder="9">
                    <Outputs>
                        <Output Name="Ceiling" UUID="1896" IntegrationID="75" OutputType="INC" Wattage="0" SortOrder="0" />
                    </Outputs>
                </Area>
                <Area Name="Child Room" UUID="437" IntegrationID="19" OccupancyGroupAssignedToID="439" SortOrder="1">
                    <DeviceGroups>
                        <DeviceGroup Name="Door" SortOrder="0">
                            <Devices>
                                <Device Name="Pico Remote" UUID="7063" SerialNumber="00000000" IntegrationID="48" DeviceType="PICO_KEYPAD" GangPosition="1" SortOrder="1">
                                    <Components>
                                        <Component ComponentNumber="2" ComponentType="BUTTON">
                                            <Button Name="Button 1" UUID="7066" Engraving="On" ButtonType="SingleAction" Direction="Press" />
                                        </Component>
                                        <Component ComponentNumber="3" ComponentType="BUTTON">
                                            <Button Name="Button 2" UUID="7069" Engraving="Favorite" ButtonType="SingleAction" />
                                        </Component>
                                    </Components>
                                </Device>
                            </Devices>
                        </DeviceGroup>
                    </DeviceGroups>
                    <Outputs>
                        <Output Name="Closet" UUID="11865" IntegrationID="65" OutputType="ELV" Wattage="0" SortOrder="0" />
                    </Outputs>
                </Area>
                <Area Name="Living Room" UUID="377" IntegrationID="13" OccupancyGroupAssignedToID="379" SortOrder="14">
                     <DeviceGroups>
                        <DeviceGroup Name="Front Door" SortOrder="0">
                            <Devices>
                                <Device Name="Keypad" UUID="7589" SerialNumber="00000000" IntegrationID="40" DeviceType="HYBRID_SEETOUCH_KEYPAD">
                                    <Components>
                                        <Component ComponentNumber="1" ComponentType="BUTTON">
                                            <Button Name="Button 1" UUID="7603" Engraving="Loft" ButtonType="Toggle" />
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
            </Areas>
        </Area>
    </Areas>
    <OccupancyGroups>
        <OccupancyGroup UUID="10015" OccupancyGroupNumber="10015" />
        <OccupancyGroup UUID="439" OccupancyGroupNumber="439" />
    </OccupancyGroups>
</Project>
"""

class TestRealWorldXml(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron('localhost', 'user', 'pass')

    def test_parse_real_world_xml(self):
        parser = LutronXmlDbParser(self.lutron, REAL_WORLD_XML)
        self.assertTrue(parser.parse())

        # Check basic hierarchy
        # parser.areas contains the sub-areas (rooms) found in the project.
        # In our XML, we have 4 rooms (Bathroom, Hallway, Child Room, Living Room)
        self.assertEqual(len(parser.areas), 4) 
        
        # Check specific room details
        bathroom = next(a for a in parser.areas if a.name == "Bathroom")
        self.assertEqual(bathroom.id, 92)
        self.assertEqual(len(bathroom.outputs), 2)
        
        child_room = next(a for a in parser.areas if a.name == "Child Room")
        self.assertEqual(len(child_room.keypads), 1)
        pico = child_room.keypads[0]
        self.assertEqual(pico.name, "Pico Remote")
        self.assertEqual(len(pico.buttons), 2)
        
        living_room = next(a for a in parser.areas if a.name == "Living Room")
        hybrid_keypad = living_room.keypads[0]
        self.assertEqual(hybrid_keypad.type, "HYBRID_SEETOUCH_KEYPAD")

if __name__ == '__main__':
    unittest.main()
