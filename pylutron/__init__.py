"""
Lutron RadioRA 2 module for interacting with the Main Repeater. Basic operations
for enumerating and controlling the loads are supported.

"""

__author__ = "Dima Zavin"
__copyright__ = "Copyright 2016, Dima Zavin"

import logging
import telnetlib
import threading
import time

_LOGGER = logging.getLogger(__name__)

class LutronException(Exception):
  """Top level module exception."""
  pass


class IntegrationIdExistsError(LutronException):
  """Asserted when there's an attempt to register a duplicate integration id."""
  pass


class ConnectionExistsError(LutronException):
  """Raised when a connection already exists (e.g. user calls connect() twice)."""
  pass


class LutronConnection(threading.Thread):
  """Encapsulates the connection to the Lutron controller."""
  USER_PROMPT = b'login: '
  PW_PROMPT = b'password: '
  PROMPT = b'GNET> '

  def __init__(self, host, user, password, recv_callback):
    """Initializes the lutron connection, doesn't actually connect."""
    threading.Thread.__init__(self)

    self._host = host
    self._user = user.encode('ascii')
    self._password = password.encode('ascii')
    self._telnet = None
    self._connected = False
    self._lock = threading.Lock()
    self._connect_cond = threading.Condition(lock=self._lock)
    self._recv_cb = recv_callback
    self._done = False

    self.setDaemon(True)

  def connect(self):
    """Connects to the lutron controller."""
    if self._connected or self.is_alive():
      raise ConnectionExistsError("Already connected")
    # After starting the thread we wait for it to post us
    # an event signifying that connection is established. This
    # ensures that the caller only resumes when we are fully connected.
    self.start()
    with self._lock:
      self._connect_cond.wait_for(lambda: self._connected)

  def send(self, cmd):
    """Sends the specified command to the lutron controller."""
    _LOGGER.debug("Sending: %s" % cmd)
    try:
      self._telnet.write(cmd.encode('ascii') + b'\r\n')
    except BrokenPipeError:
      self._disconnect()

  def _do_login(self):
    """Executes the login procedure (telnet) as well as setting up some
    connection defaults like turning off the prompt, etc."""
    self._telnet = telnetlib.Telnet(self._host)
    self._telnet.read_until(LutronConnection.USER_PROMPT)
    self._telnet.write(self._user + b'\r\n')
    self._telnet.read_until(LutronConnection.PW_PROMPT)
    self._telnet.write(self._password + b'\r\n')
    self._telnet.read_until(LutronConnection.PROMPT)

    self.send("#MONITORING,12,2")
    self.send("#MONITORING,255,2")
    self.send("#MONITORING,4,1")
    self.send("#MONITORING,5,1")
    self.send("#MONITORING,6,1")
    self.send("#MONITORING,8,1")

  def _disconnect(self):
    with self._lock:
      self._connected = False
      self._connect_cond.notify_all()
      self._telnet = None
      _LOGGER.warning("Disconnected")

  def _maybe_reconnect(self):
    """Reconnects to the controller if we have been previously disconnected."""
    with self._lock:
      if not self._connected: 
        _LOGGER.info("Connecting")
        self._lock.release()
        try:
          self._do_login()
        finally:
          self._lock.acquire()
        self._connected = True
        self._connect_cond.notify_all()
        _LOGGER.info("Connected")

  def run(self):
    """Main thread function to maintain connection and receive remote status."""
    _LOGGER.info("Started")
    while True:
      self._maybe_reconnect()
      try:
        line = self._telnet.read_until(b"\n")
      except EOFError:
        self._disconnect()
        continue
      self._recv_cb(line.decode('ascii').rstrip())


class LutronXmlDbParser(object):
  """The parser for Lutron XML database.

  The database describes all the rooms (Area), keypads (Device), and switches
  (Output). We handle the most relevant features, but some things like LEDs,
  etc. are not implemented."""

  def __init__(self, lutron, xml_db_str):
    """Initializes the XML parser, takes the raw XML data as string input."""
    self._lutron = lutron
    self._xml_db_str = xml_db_str
    self.areas = []
    self.project_name = None

  def parse(self):
    """Main entrypoint into the parser. It interprets and creates all the
    relevant Lutron objects and stuffs them into the appropriate hierarchy."""
    import xml.etree.ElementTree as ET

    root = ET.fromstring(self._xml_db_str)
    # The structure is something like this:
    # <Areas>
    #   <Area ...>
    #     <DeviceGroups ...>
    #     <Scenes ...>
    #     <ShadeGroups ...>
    #     <Outputs ...>
    #     <Areas ...>
    #       <Area ...>

    # First area is useless, it's the top-level project area that defines the
    # "house". It contains the real nested Areas tree, which is the one we want.
    top_area = root.find('Areas').find('Area')
    self.project_name = top_area.get('Name')
    areas = top_area.find('Areas')
    for area_xml in areas.getiterator('Area'):
      area = self._parse_area(area_xml)
      self.areas.append(area)      
    return True

  def _parse_area(self, area_xml):
    """Parses an Area tag, which is effectively a room, depending on how the
    Lutron controller programming was done."""
    area = Area(self._lutron,
                name=area_xml.get('Name'),
                integration_id=int(area_xml.get('IntegrationID')),
                occupancy_group_id=area_xml.get('OccupancyGroupAssignedToID'))
    for output_xml in area_xml.find('Outputs'):
      output = self._parse_output(output_xml)
      area.add_output(output)
    # device group in our case means keypad
    # device_group.get('Name') is the location of the keypad
    for device_group in area_xml.find('DeviceGroups'):
      if device_group.tag == 'DeviceGroup':
        devs = device_group.find('Devices')
      elif device_group.tag == 'Device':
        devs = [device_group]
      else:
        _LOGGER.info("Unknown tag in DeviceGroups child %s" % devs)
        devs = []
      for device_xml in devs:
        if device_xml.tag != 'Device':
          continue
        if device_xml.get('DeviceType') in ('SEETOUCH_KEYPAD', 'PICO_KEYPAD'):
          keypad = self._parse_keypad(device_xml)
          area.add_keypad(keypad)
        elif device_xml.get('DeviceType') == 'MOTION_SENSOR':
          motion_sensor = self._parse_motion_sensor(device_xml)
          area.add_sensor(motion_sensor)
        #elif device_xml.get('DeviceType') == 'VISOR_CONTROL_RECEIVER':
    return area

  def _parse_output(self, output_xml):
    """Parses an output, which is generally a switch controlling a set of
    lights/outlets, etc."""
    output = Output(self._lutron,
                    name=output_xml.get('Name'),
                    watts=output_xml.get('Wattage'),
                    output_type=output_xml.get('OutputType'),
                    integration_id=int(output_xml.get('IntegrationID')))
    return output

  def _parse_keypad(self, keypad_xml):
    """Parses a keypad device (the Visor receiver is technically a keypad too)."""
    keypad = Keypad(self._lutron,
                    name=keypad_xml.get('Name'),
                    integration_id=int(keypad_xml.get('IntegrationID')))
    components = keypad_xml.find('Components')
    if not components:
      return keypad
    for comp in components:
      if comp.tag != 'Component' or comp.get('ComponentType') != 'BUTTON':
        continue
      button = self._parse_button(comp)
      keypad.add_button(button)
    return keypad

  def _parse_button(self, component_xml):
    """Parses a button device that part of a keypad."""
    button_xml = component_xml.find('Button')
    name = button_xml.get('Engraving')
    if not name:
      name = "Unknown Button"
    button = Button(self._lutron,
                    name=name,
                    num=int(component_xml.get('ComponentNumber')),
                    button_type=button_xml.get('ButtonType'),
                    direction=button_xml.get('Direction'))
    return button

  def _parse_motion_sensor(self, sensor_xml):
    """Parses a motion sensor object.

    TODO: We don't actually do anything with these yet. There's a lot of info
    that needs to be managed to do this right. We'd have to manage the occupancy
    groups, what's assigned to them, and when they go (un)occupied. We'll handle
    this later.
    """
    return MotionSensor(self._lutron,
                        name=sensor_xml.get('Name'),
                        integration_id=int(sensor_xml.get('IntegrationID')))


class Lutron(object):
  """Main Lutron Controller class.

  This object owns the connection to the controller, the rooms that exist in the
  network, handles dispatch of incoming status updates, etc.
  """

  # All Lutron commands start with one of these characters
  # See http://www.lutron.com/TechnicalDocumentLibrary/040249.pdf
  OP_EXECUTE = '#'
  OP_QUERY = '?'
  OP_RESPONSE = '~'

  def __init__(self, host, user, password):
    """Initializes the Lutron object. No connection is made to the remote
    device."""
    self._host = host
    self._user = user
    self._password = password
    self._name = None
    self._conn = LutronConnection(host, user, password, self._recv)
    self._ids = {}
    self._subscribers = {}
    self.areas = []

  def subscribe(self, obj, handler):
    """Subscribes to status updates of the requested object.

    The handler will be invoked when the controller sends a notification
    regarding changed state. The user can then further query the object for the
    state itself."""
    self._subscribers[obj] = handler

  def register_id(self, cmd_type, obj):
    """Registers an object (through its integration id) to receive update
    notifications. This is the core mechanism how Output and Keypad objects get
    notified when the controller sends status updates."""
    ids = self._ids.setdefault(cmd_type, {})
    if obj.id in ids:
      raise IntegrationIdExistsError
    self._ids[cmd_type][obj.id] = obj

  def _recv(self, line):
    """Invoked by the connection manager to process incoming data."""
    if line == '':
      return
    # Only handle query response messages, which are also sent on remote status
    # updates (e.g. user manually pressed a keypad button)
    if line[0] != Lutron.OP_RESPONSE:
      _LOGGER.debug("ignoring %s" % line)
      return
    parts = line[1:].split(',')
    cmd_type = parts[0]
    integration_id = int(parts[1])
    args = parts[2:]
    if cmd_type not in self._ids:
      _LOGGER.info("Unknown cmd %s (%s)" % (cmd_type, line))
      return
    ids = self._ids[cmd_type]
    if integration_id not in ids:
      _LOGGER.warning("Unknown id %d (%s)" % (integration_id, line))
      return
    obj = ids[integration_id]
    # First let the device update itself
    handled = obj.handle_update(args)
    # Now notify anyone who cares that device  may have changed
    if handled and obj in self._subscribers:
      self._subscribers[obj](obj)

  def connect(self):
    """Connects to the Lutron controller to send and receive commands and status"""
    self._conn.connect()

  def send(self, op, cmd, integration_id, *args):
    """Formats and sends the requested command to the Lutron controller."""
    out_cmd = ",".join(
        (cmd, str(integration_id)) + tuple((str(x) for x in args)))
    self._conn.send(op + out_cmd)

  def load_xml_db(self):
    """Load the Lutron database from the server."""

    import urllib.request
    xmlfile = urllib.request.urlopen('http://' + self._host + '/DbXmlInfo.xml')
    xml_db = xmlfile.read()
    xmlfile.close()
    _LOGGER.info("Loaded xml db")

    parser = LutronXmlDbParser(lutron=self, xml_db_str=xml_db)
    assert(parser.parse())     # throw our own exception
    self.areas = parser.areas
    self._name = parser.project_name

    _LOGGER.info('Found Lutron project: %s, %d areas' % (
        self._name, len(self.areas)))

    return True


class _RequestHelper(object):
  """A class to help with sending queries to the controller and waiting for
  responses.

  It is a wrapper used to help with executing a user action
  and then waiting for an event when that action completes.

  The user calls request() and gets back a threading.Event on which they then
  wait.

  If multiple clients of a lutron object (say an Output) want to get a status
  update on the current brightness (output level), we don't want to spam the
  controller with (near)identical requests. So, if a request is pending, we
  just enqueue another waiter on the pending request and return a new Event
  object. All waiters will be woken up when the reply is received and the
  wait list is cleared.

  NOTE: Only the first enqueued action is executed as the assumption is that the
  queries will be identical in nature.
  """

  def __init__(self):
    """Initialize the request helper class."""
    self.__lock = threading.Lock()
    self.__events = []

  def request(self, action):
    """Request an action to be performed, in case one."""
    ev = threading.Event()
    first = False
    with self.__lock:
      if len(self.__events) == 0:
        first = True
      self.__events.append(ev)
    if first:
      action()
    return ev

  def notify(self):
    with self.__lock:
      events = self.__events
      self.__events = []
    for ev in events:
      ev.set()


class LutronEntity(object):
  """Base class for all the Lutron objects we'd like to manage. Just holds basic
  common info we'd rather not manage repeatedly."""

  def __init__(self, lutron, name, integration_id):
    """Initializes the base class with common, basic data."""
    self._lutron = lutron
    self._name = name
    self._integration_id = integration_id

  @property
  def name(self):
    """Returns the entity name (e.g. Pendant)."""
    return self._name

  @property
  def id(self):
    """The integration id"""
    return self._integration_id

  def handle_update(self, args):
    """The handle_update callback is invoked when an event is received
    for the this entity.

    Returns:
      True - If event was valid and was handled.
      False - otherwise.
    """
    return False


class Output(LutronEntity):
  """This is the output entity in Lutron universe. This generally refers to a
  switched/dimmed load, e.g. light fixture, outlet, etc."""
  CMD_TYPE = 'OUTPUT'
  ACTION_ZONE_LEVEL = 1

  def __init__(self, lutron, name, watts, output_type, integration_id):
    """Initializes the Output."""
    super(Output, self).__init__(lutron, name, integration_id)
    self._watts = watts
    self._output_type = output_type
    self._level = 0.0
    self._query_waiters = _RequestHelper()

    self._lutron.register_id(Output.CMD_TYPE, self)

  def __str__(self):
    """Returns a pretty-printed string for this object."""
    return 'Output name: "%s" watts: %d type: "%s" id: %d' % (
        self._name, self._watts, self._type, self._integration_id)

  def __repr__(self):
    """Returns a stringified representation of this object."""
    return str({'name': self._name, 'watts': self._watts,
                'type': self._output_type, 'id': self._integration_id})

  def handle_update(self, args):
    """Handles an event update for this object, e.g. dimmer level change."""
    _LOGGER.debug("handle_update %d -- %s" % (self._integration_id, args))
    state = int(args[0])
    if state != Output.ACTION_ZONE_LEVEL:
      return False
    level = float(args[1])
    _LOGGER.debug("Updating %d(%s): s=%d l=%f" % (
        self._integration_id, self._name, state, level))
    self._level = level
    self._query_waiters.notify()
    return True

  def __do_query_level(self):
    """Helper to perform the actual query the current dimmer level of the
    output. For pure on/off loads the result is either 0.0 or 100.0."""
    self._lutron.send(Lutron.OP_QUERY, Output.CMD_TYPE, self._integration_id,
            Output.ACTION_ZONE_LEVEL)

  def last_level(self):
    """Returns last cached value of the output level, no query is performed."""
    return self._level

  @property
  def level(self):
    """Returns the current output level by querying the remote controller."""
    ev = self._query_waiters.request(self.__do_query_level)
    ev.wait(1.0)
    return self._level

  @level.setter
  def level(self, new_level):
    """Sets the new output level."""
    if self._level == new_level:
      return
    self._lutron.send(Lutron.OP_EXECUTE, Output.CMD_TYPE, self._integration_id,
        Output.ACTION_ZONE_LEVEL, "%.2f" % new_level)
    self._level = new_level

## At some later date, we may want to also specify fade and delay times    
#  def set_level(self, new_level, fade_time, delay):
#    self._lutron.send(Lutron.OP_EXECUTE, Output.CMD_TYPE,
#        Output.ACTION_ZONE_LEVEL, new_level, fade_time, delay)

  @property
  def watts(self):
    """Returns the configured maximum wattage for this output (not an actual
    measurement)."""
    return self._watts

  @property
  def type(self):
    """Returns the output type. At present AUTO_DETECT or NON_DIM."""
    return self._output_type

  @property
  def is_dimmable(self):
    """Returns a boolean of whether or not the output is dimmable."""
    return self.type != 'NON_DIM' and not self.type.startswith('CCO_')


class Button(object):
  """This object represents a keypad button that we can trigger and handle
  events for (button presses)."""
  def __init__(self, lutron, name, num, button_type, direction):
    self._lutron = lutron
    self._name = name
    self._num = num
    self._button_type = button_type
    self._direction = direction

  def __str__(self):
    """Pretty printed string value of the Button object."""
    return 'Button name: "%s" num: %d action: "%s"' % (
        self._name, self._num, self._action)

  def __repr__(self):
    """String representation of the Button object."""
    return str({'name': self._name, 'num': self._num, 'action': self._action})

  @property
  def name(self):
    """Returns the name of the button."""
    return self._name

  @property
  def number(self):
    """Returns the button number."""
    return self._num

  @property
  def button_type(self):
    """Returns the button type (Toggle, MasterRaiseLower, etc.)."""
    return self._button_type


class Keypad(LutronEntity):
  """Object representing a Lutron keypad.
  
  Currently we don't really do much with it except handle the events
  (and drop them on the floor).
  """
  CMD_TYPE = 'DEVICE'

  def __init__(self, lutron, name, integration_id):
    """Initializes the Keypad object."""
    super(Keypad, self).__init__(lutron, name, integration_id)
    self._buttons = []
    self._lutron.register_id(Keypad.CMD_TYPE, self)

  def add_button(self, button):
    """Adds a button that's part of this keypad. We'll use this to
    dispatch button events."""
    self._buttons.append(button)

  @property
  def buttons(self):
    """Return a tuple of buttons for this keypad."""
    return tuple(button for button in self._buttons)

  def handle_update(self, args):
    """The callback invoked by the main event loop if there's an event from this keypad."""
    component = int(args[0])
    action = int(args[1])
    params = [int(x) for x in args[2:]]
    _LOGGER.debug("Updating %d(%s): c=%d a=%d params=%s" % (
        self._integration_id, self._name, component, action, params))
    return True


class MotionSensor(object):
  """Placeholder class for the motion sensor device.
  
  TODO: Actually implement this.
  """
  def __init__(self, lutron, name, integration_id):
    """Initializes the motion sensor object."""
    self._lutron = lutron
    self._name = name
    self._integration_id = integration_id


class Area(object):
  """An area (i.e. a room) that contains devices/outputs/etc."""
  def __init__(self, lutron, name, integration_id, occupancy_group_id):
    self._lutron = lutron
    self._name = name
    self._integration_id = integration_id
    self._occupancy_group_id = occupancy_group_id
    self._outputs = []
    self._keypads = []
    self._sensors = []

  def add_output(self, output):
    """Adds an output object that's part of this area, only used during
    initial parsing."""
    self._outputs.append(output)

  def add_keypad(self, keypad):
    """Adds a keypad object that's part of this area, only used during
    initial parsing."""
    self._keypads.append(keypad)

  def add_sensor(self, sensor):
    """Adds a motion sensor object that's part of this area, only used during
    initial parsing."""
    self._sensors.append(sensor)

  @property
  def name(self):
    """Returns the name of this area."""
    return self._name

  @property
  def id(self):
    """The integration id of the area."""
    return self._integration_id

  @property
  def outputs(self):
    """Return the tuple of the Outputs from this area."""
    return tuple(output for output in self._outputs)

  @property
  def keypads(self):
    """Return the tuple of the Keypads from this area."""
    return tuple(keypad for keypad in self._keypads)

  @property
  def sensors(self):
    """Return the tuple of the MotionSensors from this area."""
    return tuple(sensor for sensor in self._sensors)

