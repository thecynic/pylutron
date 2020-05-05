"""
Lutron RadioRA 2 module for interacting with the Main Repeater. Basic operations
for enumerating and controlling the loads are supported.

"""

__author__ = "Dima Zavin"
__copyright__ = "Copyright 2016, Dima Zavin"

from enum import Enum
import logging
import socket
import telnetlib
import threading
import time
import string
import io
import parse

from typing import Any, Callable, Dict, Type

_LOGGER = logging.getLogger(__name__)

# We brute force exception handling in a number of areas to ensure
# connections can be recovered
_EXPECTED_NETWORK_EXCEPTIONS = (
  BrokenPipeError,
  # OSError: [Errno 101] Network unreachable
  OSError,
  EOFError,
  TimeoutError,
  socket.timeout,
)

class Processor(object):
  """ Encapsulates the specific communication protocols associated with a Lutron Processor. 
    This is the base class that contains the interfaces and datastructures. Subclasses 
    provide for implementation specific connections to the processor and protocol translations.
    
    The Processor class keeps track of the objects associated with that processes and a 
    mapping from id to obj. Different Processors may have different notions what an id is.
    
    Each subclass should define a static variable in this class with its name as a variable
    and the value as its stringified name. It should also regiter a factory to create the
    processor. 

    Example:
       For processor subclass ProcessorFoo(Processor).
       1) Create a variable: Processor.Foo = "Foo"
       2) Register in the factory: Processor.Factory[Processor.Foo] = ProcessorFoo
    """

  # static factory for creating the processors.
  # example:
  #   processor = Processor.Factory[Processor.HWI]()
  Factory = {}

  USER_PROMPT = b'login: '
  PW_PROMPT = b'password: '

  def __init__(self):
    """ Initialize """
    self._ids = {}                               # dict of ids to hold id -> obj mappings

  def obj(self, obj_id, cmd_type=None):
      """ return the obj from an id. If the cmd_type isn't passed in, it'll look through all
      cmd types for the id"""
      obj_id = obj_id.strip()
      if cmd_type:
        return self._ids[cmd_type][obj_id]
      else:
        for cmd_dict in self._ids:
            if obj_id in cmd_dict:
                return cmd_dict[obj_id]

  @property
  def prompt(self):
    return self._prompt

  @property
  def cmd_types(self):
     """ return all the cmd_types available"""
     return self._ids.keys()

  def register_id(self, cmd_type, obj):
    """Handles the management of ids. HWI processors use addresses whereas the newer
    processors use ids. This abstracts out the differences."""
    self._register_id(cmd_type, obj.id, obj)

  def _register_id(self, cmd_type, obj_id, obj):
    """ Subclasses that have a different notion of an id will override this. 
        Store a map of id's to objects. """
    ids = self._ids.setdefault(cmd_type, {})

    if obj_id in ids:
      raise IntegrationIdExistsError
    self._ids[cmd_type][obj_id] = obj
    _LOGGER.debug("Registered %s of type %s" % (obj_id, cmd_type))

  def cmd(self, command_str):
    """ Take in a command and translate if needed. The native protocol is QS,
    so if the command is in HWI format, convert to QS. All commands are returned as
    a list of one or more commands."""

    return [command_str]

  def connect(self, telnet, user, password):
    """Connect to the processor. """

    # Wait for the login prompt, send the username. Wait for the password. 
    telnet.read_until(self.USER_PROMPT, timeout=3)
    telnet.write(user + b'\r\n')
    telnet.read_until(self.PW_PROMPT, timeout=3)
    telnet.write(password + b'\r\n')

  def parser(self, lutron, xml_db_str):
      """ Returns a Parser object to parse the database for this processor.
          Subclasses must implement this. """
      pass

  def initialize(self, connection):
      """ Called after a successful connection to setup any additional configuration. """
      pass

class QSProcessor(Processor):
  """ Processor for QS systems """
  Processor.QS = "QS"

  def __init__(self):
    """ Initialize QS processor. """
    super().__init__()

    self._prompt = b'QNET> '                     # prompt to look for when logged in

  def parser(self, lutron, xml_db_str):
      """ Parse QS/RA2 database. """
      return QSXmlDbParser(lutron, xml_db_str)

  def initialize(self):
     """ Turn on feedback """
     connection._send_locked("#MONITORING,12,2")
     connection._send_locked("#MONITORING,255,2")
     connection._send_locked("#MONITORING,3,1")
     connection._send_locked("#MONITORING,4,1")
     connection._send_locked("#MONITORING,5,1")
     connection._send_locked("#MONITORING,6,1")
     connection._send_locked("#MONITORING,8,1")


class RA2Processor(QSProcessor):
  """ Processor for RA2 systems """
  Processor.RA2 = "RA2"

  def __init__(self):
    """ Initialize RA2 processor. """
    super().__init__()
    self._prompt = b'GNET> '                      # prompt to look for when logged in

class HWIProcessor(Processor):
  """ Encapsulates the specific communication protocols associated with a Lutron Processor. The base comms protocol is RA2/QS,
    when talking to an HWI processor, there is a protocol conversion."""
  Processor.HWI = "HWI"

  class CommandFormatter(string.Formatter):
    """ Helper class to format strings for conversions. Adds to the Formatter spec:
          - Added a psuedo arg_name 'all'. An arg_name such as {all} will return all the arguments
          - Added two new conversion specifications: !o and !F.
             o !o print the object associated with an object id.
             o !F convert a string to a float. """

    def __init__(self, processor):
        """ Init, requires an initialized processor"""
        self._processor = processor

    def get_field(self, field_name, *args, **kwargs):
        """ A pseudo arg_name {all} that will return all input args. Example:
            input: "This is the input: {all}".format("a", "b", "c", "d")
            output: This is the input: a b c d"""

        if field_name == "all":
            return ((" ".join(args[0]), "all"))
        else:
            return super().get_field(field_name, *args, **kwargs)

    def convert_field(self, value, conversion):
        """ Additional field conversions. !o for object id, and !F for string to float. Example:
            "The obj: {0!o} from obj_id: {0}".format(obj_id)

            "A real float: {0!F:.2f}.format("123.4567")"""

        if conversion == 'o':
            return self._processor.obj(value)
        elif conversion == 'F':
            return float(value)
        else:
            return super().convert_field(value, conversion)

  def __init__(self):
    """ Initialize HWI processor. """
    super().__init__()
    self._prompt = b'LNET> '                     # prompt to look for when logged in
    self._format = self.CommandFormatter(self)   # internal string formatter

      # rewrite rules. matches on the first argument.
      #
      #    Input                 Output
      #    -----                 ----       
      #    literal               literal
      #    QS Command String     HWI command string
      #    QS Device Action      HWI Button Press
      #    QS Output Request     HWI Request Intensity
      #    QS Output Action      HWI Fade to Intensity with 0 time delay
      #    HWI level change      QS Output Response 
      #    <all others pass through>
      #
      # Note. LED processing not considered
      #
    self._cmds = { 'PROMPT'   : ["PROMPTOFF"],
                   'MON_OFF'  : ["DLMOFF", "KLMOFF", "KBMOFF", "GSMOFF"],
                   'BTN_MON'  : ["KBMON"],
                   'LED_MON'  : ["KLMON"],
                   'ZONE_MON' : ["DLMON"],
                   '#DEVICE'  : ["KBP, {1}, {2}"],
                   '?OUTPUT'  : ["RDL, {1}"],
                   '#OUTPUT'  : ["FADEDIM, {3!F:.0f}, 0, 0, {1}"],
                   'DL'       : ["%sOUTPUT, {1}, %s, {2}" % (Lutron.OP_RESPONSE, Output._ACTION_ZONE_LEVEL)],
                    }

  def canonicalize_addr(self, addr):
    """ Turns a HWI address into the canonical format. i.e., square brackets, colon separated,
      and two digits.
      1:2:34 -> [01:02:34]"""

    # if it already has brackets or whitespace, strip it out so that it can be reformatted
    addr = addr.strip("[]%s" % string.whitespace)

    # this mess turns a HWI address into the canonical format. i.e., 1:2:3 -> [ 01:02:03 ]
    return "[{}]".format(":".join(["{:02}".format(int(a)) for a in addr.split(':')]))

  def register_id(self, cmd_type, obj):
    """Handles the management of ids. HWI processors use addresses whereas the newer
    processors use ids. This abstracts out the differences."""

    self._register_id(cmd_type, self.canonicalize_addr(obj.address), obj)

  def cmd(self, command_str):
    """ Take in a command and translate if needed. The native protocol is QS,
    so if the command is in HWI format, convert to QS. All commands are returned as
    a list of one or more commands."""

    # empty strings are often returned from the main loop
    if command_str == '':
        return [command_str]

    # ignore the return of the prompt
    if command_str == self._prompt:
        return []

    #
    # Find the command name for lookup. If there's nothing that looks like a command, deem it
    # a passthrough and return the original string. All commands need not be implemented in the
    # _cmds table.
    #

    # OP_EXECUTE or OP_QUERY commands are translated for HWI
    if command_str[0] == Lutron.OP_EXECUTE or command_str[0] == Lutron.OP_QUERY:
        cmd_name = command_str.split(',')[0]

    # Some string literal commands w/ arguments don't start with OP_EXECUTE or OP_QUERY
    elif command_str.split(",")[0] in self._cmds:
        cmd_name = command_str.split(",")[0]

    # String literal commands without arguments
    elif command_str in self._cmds:
        cmd_name = command_str

    # There's no translation, pass it back as is
    else:
        return([command_str])

    # Each native command can turn into one or more translated commands.
    # The commands returned from the table are format strings to determine how to
    # handle the args. So, get the command and then format the final string with args.
    cmd_list = self._cmds[cmd_name]
    cooked_cmds = [self._format.vformat((n), command_str.split(','), {}) for n in cmd_list]
    try:
        _LOGGER.debug("Converting cmd %s to %s" % (command_str, cooked_cmds))
        return cooked_cmds
    except:
      return [command_str]

  def connect(self, telnet, user, password):
    """Connect to the processor. HWI requires login,password whereas QS/RA2 is a normal
    login followed by password"""

    # Wait for the login prompt, send the username,password and then turn on the prompt.
    telnet.read_until(self.USER_PROMPT, timeout=3)
    login_string="%s,%s".encode('ascii') % (user, password)
    telnet.write(login_string + b'\r\n')

    # turn on prompting, this is used to find the end of the returned line
    telnet.write("PROMPTON".encode('ascii') + b'\r\n')

  def parser(self, lutron, xml_db_str):
      return HWIXmlDbParser(lutron, xml_db_str)

  def initialize(self, connection):
    """ Setup monitoring """
    connection._send_locked("MON_OFF")
    connection._send_locked("BTN_MON")
    connection._send_locked("LED_MON")
    connection._send_locked("ZONE_MON")

# register all the processors into the Processor factory. 
Processor.Factory[Processor.QS]  = QSProcessor
Processor.Factory[Processor.RA2] = RA2Processor
Processor.Factory[Processor.HWI] = HWIProcessor

class LutronException(Exception):
  """Top level module exception."""
  pass


class IntegrationIdExistsError(LutronException):
  """Asserted when there's an attempt to register a duplicate integration id."""
  pass


class ConnectionExistsError(LutronException):
  """Raised when a connection already exists (e.g. user calls connect() twice)."""
  pass


class InvalidSubscription(LutronException):
  """Raised when an invalid subscription is requested (e.g. calling
  Lutron.subscribe on an incompatible object."""
  pass


class LutronConnection(threading.Thread):
  """Encapsulates the connection to the Lutron controller."""

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
    self._processor = None

    self.setDaemon(True)

  @property
  def processor(self):
    return self._processor

  def setProcessor(self, processor):
    self._processor = processor

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

  def _send_locked(self, cmd):
    """Sends the specified command to the lutron controller.

    Assumes self._lock is held.
    """
    _LOGGER.debug("Sending: %s" % cmd)
    try:
      cooked_cmds = self._processor.cmd(cmd)
      for cooked_cmd in cooked_cmds:
        _LOGGER.debug("Sending Command: %s -> %s" % (cmd, cooked_cmd))
        self._telnet.write(cooked_cmd.encode('ascii') + b'\r\n')
    except _EXPECTED_NETWORK_EXCEPTIONS:
      _LOGGER.exception("Error sending {}".format(cmd))
      self._disconnect_locked()

  def send(self, cmd):
    """Sends the specified command to the lutron controller.

    Must not hold self._lock.
    """
    with self._lock:
      if not self._connected:
        _LOGGER.debug("Ignoring send of '%s' because we are disconnected." % cmd)
        return
      self._send_locked(cmd)

  def _do_login_locked(self):
    """Executes the login procedure (telnet) as well as setting up some
    connection defaults like turning off the prompt, etc."""
    _LOGGER.info("Logging in over telnet")
    self._telnet = telnetlib.Telnet(self._host, timeout=2)  # 2 second timeout

    # Ensure we know that connection goes away somewhat quickly
    try:
      sock = self._telnet.get_socket()
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
      # Some operating systems may not include TCP_KEEPIDLE (macOS, variants of Windows)
      if hasattr(socket, 'TCP_KEEPIDLE'):
        # Send keepalive probes after 60 seconds of inactivity
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
      # Wait 10 seconds for an ACK
      sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
      # Send 3 probes before we give up
      sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except OSError:
      _LOGGER.exception('error configuring socket')

    self._processor.connect(self._telnet, self._user, self._password)

    _LOGGER.debug("Logged in, waiting for prompt")
    try:
       prompt = self._telnet.read_until(self._processor.prompt, timeout=3)
       _LOGGER.debug("Received prompt: %s", prompt)
       if not self._processor.prompt in prompt:
          _LOGGER.warning("Bad Password (%s). Disconnecting." % prompt)
          self._telnet = None
          return
    except EOFError:
        _LOGGER.exception("Logged out while waiting for prompt")
        self._telnet = None
        return

    # send commands to initialize the processor to the state that's needed
    self._processor.initialize(self)

    # flush any commands coming back from the initialization. The extra commands
    # can confuse the rest of the code
    while True:
        if self._telnet.read_until(b"\n", timeout=1) == b'':
           break

  def _disconnect_locked(self):
    """Closes the current connection. Assume self._lock is held."""
    was_connected = self._connected
    self._connected = False
    self._connect_cond.notify_all()
    self._telnet = None
    if was_connected:
      _LOGGER.warning("Disconnected")

  def _maybe_reconnect(self):
    """Reconnects to the controller if we have been previously disconnected."""
    with self._lock:
      if not self._connected:
        _LOGGER.info("Connecting")
        # Make sure that it was able to log in. If the telnet connection got torn
        # down during login, it's not a successful connection
        self._do_login_locked()
        if self._telnet:
           self._connected = True
           _LOGGER.info("Connected")
        self._connect_cond.notify_all()

  def _main_loop(self):
    """Main body of the the thread function.

    This will maintain connection and receive remote status updates.
    """
    while True:
      line = b''
      try:
        self._maybe_reconnect()
        # If someone is sending a command, we can lose our connection so grab a
        # copy beforehand. We don't need the lock because if the connection is
        # open, we are the only ones that will read from telnet (the reconnect
        # code runs synchronously in this loop).
        t = self._telnet
        if t is not None:
          try: 
             line = t.read_until(b"\n", timeout=3)
          except EOFError:
              self._connected = False
              _LOGGER.exception('Connection closed while reading next line.')
        else:
          raise EOFError('Telnet object already torn down')
      except _EXPECTED_NETWORK_EXCEPTIONS:
        _LOGGER.exception("Uncaught exception")
        try:
          # if it didn't connect, wait a bit to see if the transient error cleared up.
          time.sleep(1)
          self._lock.acquire()
          self._disconnect_locked()
          # don't spam reconnect
          time.sleep(1)
          continue
        finally:
          self._lock.release()
      self._recv_cb(self._processor.cmd(line.decode('ascii').rstrip())[0])

  def run(self):
    """Main entry point into our receive thread.

    It just wraps _main_loop() so we can catch exceptions.
    """
    _LOGGER.info("Started")
    try:
      self._main_loop()
    except Exception:
      _LOGGER.exception("Uncaught exception")
      raise


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

  def __str__(self):
    return "%s:\n%s" % (self.project_name, 
        "\n".join([str(a) for a in self._areas]))

class HWIXmlDbParser(LutronXmlDbParser):
  """ Parse HWI XML DB's """

  def __init__(self, lutron, xml_db_str):
    super().__init__(lutron, xml_db_str)

  def parse(self):
    """Main entrypoint into the parser. It interprets and creates all the
    relevant Lutron objects and stuffs them into the appropriate hierarchy."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(self._xml_db_str)
    # The structure is something like this:
    # <Area>
    #   <Room ...>
    #     <Scenes ...>
    #     <ShadeGroups ...>
    #     <Outputs ...>
    #        <Output ...>
    #     <Areas ...>
    #       <Area ...>

    self.project_name = root.find('ProjectName').text

    for area_xml in root.getiterator('Area'):
      self._parse_area(area_xml)
    return True

  def _parse_area(self, area_xml):
    """Parses an Area tag, which is effectively a room, depending on how the
    Lutron controller programming was done."""

    area_name = area_xml.find('Name').text
    for room_xml in area_xml.getiterator('Room'):
        area = Area(self._lutron,
                  name="%s-%s" % (area_name, room_xml.find('Name').text),
                  integration_id=int(room_xml.find('Id').text),
                  occupancy_group_id=None)

        outputs = room_xml.find('Outputs')
        for output_xml in outputs.getiterator('Output'):
            output = self._parse_output(output_xml)
            area.add_output(output)
        self._parse_devices(area, room_xml)
        self.areas.append(area)

  def _parse_devices(self, area, room_xml):
    control_stations = room_xml.find('Inputs')
    for cs_xml in control_stations.getiterator('ControlStation'):
      devices = cs_xml.find('Devices')
      for device_xml in devices.getiterator('Device'):
        keypad = self._parse_keypad(device_xml, cs_xml)
        area.add_keypad(keypad)

  def _parse_output(self, output_xml):
    """Parses an output, which is generally a switch controlling a set of
    lights/outlets, etc."""

    output = Output(self._lutron,
                    name=output_xml.find('Name').text,
                    integration_id=output_xml.find('Address').text,
                    address=output_xml.find('Address').text,
                    output_type=output_xml.find('Type').text,
                    watts=int(output_xml.find('FixtureWattage').text))
    return output
  def _parse_keypad(self, keypad_xml, cs_xml):
    """Parses a keypad or dimmer."""
    keypad = Keypad(self._lutron,
                    name=cs_xml.find('Name').text,
                    keypad_type=keypad_xml.find('Type').text,
                    location=keypad_xml.find('GangPosition').text,
                    integration_id=keypad_xml.find('Address').text,
                    address=keypad_xml.find('Address').text)

    buttons = keypad_xml.find('Buttons')
    for buttons_xml in buttons.getiterator('Button'):
        button = self._parse_button(keypad, buttons_xml)
        if button: keypad.add_button(button)

    return keypad

  def _parse_button(self, keypad, button_xml):
      button_type = button_xml.find('Type').text

      if button_type != 'Not Programmed':
        button = Button(self._lutron, keypad,
                        name=button_xml.find('Name').text,
                        num=int(button_xml.find('Number').text),
                        button_type=button_xml.find('Type').text.replace("Default ", ""),
                        direction='direction')

        return button

class QSXmlDbParser(LutronXmlDbParser):
  """ Parse QS/RA2 XML DB's """

  def __init__(self, lutron, xml_db_str):
    super().__init__(lutron, xml_db_str)

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
        if device_xml.get('DeviceType') in (
            'HWI_SEETOUCH_KEYPAD',
            'SEETOUCH_KEYPAD',
            'SEETOUCH_TABLETOP_KEYPAD',
            'PICO_KEYPAD',
            'HYBRID_SEETOUCH_KEYPAD',
            'MAIN_REPEATER',
            'HOMEOWNER_KEYPAD'):
          keypad = self._parse_keypad(device_xml, device_group)
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
                    watts=int(output_xml.get('Wattage')),
                    output_type=output_xml.get('OutputType'),
                    integration_id=int(output_xml.get('IntegrationID')))
    return output

  def _parse_keypad(self, keypad_xml, device_group):
    """Parses a keypad device (the Visor receiver is technically a keypad too)."""
    keypad = Keypad(self._lutron,
                    name=keypad_xml.get('Name'),
                    keypad_type=keypad_xml.get('DeviceType'),
                    location=device_group.get('Name'),
                    integration_id=int(keypad_xml.get('IntegrationID')))
    components = keypad_xml.find('Components')
    if components is None:
      return keypad
    for comp in components:
      if comp.tag != 'Component':
        continue
      comp_type = comp.get('ComponentType')
      if comp_type == 'BUTTON':
        button = self._parse_button(keypad, comp)
        keypad.add_button(button)
      elif comp_type == 'LED':
        led = self._parse_led(keypad, comp)
        keypad.add_led(led)
    return keypad

  def _parse_button(self, keypad, component_xml):
    """Parses a button device that part of a keypad."""
    button_xml = component_xml.find('Button')
    name = button_xml.get('Engraving')
    button_type = button_xml.get('ButtonType')
    direction = button_xml.get('Direction')
    # Hybrid keypads have dimmer buttons which have no engravings.
    if button_type == 'SingleSceneRaiseLower':
      name = 'Dimmer ' + direction
    if not name:
      name = "Unknown Button"
    button = Button(self._lutron, keypad,
                    name=name,
                    num=int(component_xml.get('ComponentNumber')),
                    button_type=button_type,
                    direction=direction)
    return button

  def _parse_led(self, keypad, component_xml):
    """Parses an LED device that part of a keypad."""
    component_num = int(component_xml.get('ComponentNumber'))
    led_base = 80
    if keypad.type == 'MAIN_REPEATER':
      led_base = 100
    led_num = component_num - led_base
    led = Led(self._lutron, keypad,
              name=('LED %d' % led_num),
              led_num=led_num,
              component_num=component_num)
    return led

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

  def __init__(self, host, user, password, processor_type=None):
    """Initializes the Lutron object. No connection is made to the remote
    device."""
    self._host = host
    self._user = user
    self._password = password
    self._name = None
    self._conn = LutronConnection(host, user, password, self._recv)
    self._ids = {}
    self._legacy_subscribers = {}
    self._areas = []
    self._processor_type = processor_type

  @property
  def areas(self):
    """Return the areas that were discovered for this Lutron controller."""
    return self._areas

  @property
  def name(self):
    """Return the name of the project running on this Lutron controller."""
    return self._name

  def id_to_obj(self, obj_id, cmd_type=None):
      return self._conn.processor.obj(obj_id, cmd_type)

  @property
  def processor_type(self):
    return self._processor_type

  @property
  def connected(self):
      return self._conn._connected

  def subscribe(self, obj, handler):
    """Subscribes to status updates of the requested object.

    DEPRECATED

    The handler will be invoked when the controller sends a notification
    regarding changed state. The user can then further query the object for the
    state itself."""
    if not isinstance(obj, LutronEntity):
      raise InvalidSubscription("Subscription target not a LutronEntity")
    _LOGGER.warning("DEPRECATED: Subscribing via Lutron.subscribe is obsolete. "
                    "Please use LutronEntity.subscribe")
    if obj not in self._legacy_subscribers:
      self._legacy_subscribers[obj] = handler
      obj.subscribe(self._dispatch_legacy_subscriber, None)

  def register_id(self, cmd_type, obj):
    """Registers an object (through its integration id) to receive update
    notifications. This is the core mechanism how Output and Keypad objects get
    notified when the controller sends status updates."""
    self._conn.processor.register_id(cmd_type, obj)

  def _dispatch_legacy_subscriber(self, obj, *args, **kwargs):
    """This dispatches the registered callback for 'obj'. This is only used
    for legacy subscribers since new users should register with the target
    object directly."""
    if obj in self._legacy_subscribers:
      self._legacy_subscribers[obj](obj)

  def _recv(self, line):
    """Invoked by the connection manager to process incoming data."""
    if line == '' or self._conn._processor.prompt.decode('utf-8') in line:
      return
    _LOGGER.debug("Received: %s" % line)
    # Only handle query response messages, which are also sent on remote status
    # updates (e.g. user manually pressed a keypad button)
    if line[0] != Lutron.OP_RESPONSE:
      _LOGGER.debug("ignoring %s" % line)
      return
    parts = line[1:].split(',')
    cmd_type = parts[0]
    integration_id = parts[1]
    args = parts[2:]

    if cmd_type not in self._conn.processor.cmd_types:
      _LOGGER.info("Unknown cmd %s (%s)" % (cmd_type, line))
      return
  
    obj = self.id_to_obj(integration_id, cmd_type)
    if not obj:
      _LOGGER.warning("Unknown id %d (%s)" % (integration_id, line))
      return
    handled = obj.handle_update(args)

  def connect(self):
    """Connects to the Lutron controller to send and receive commands and status"""
    self._conn.connect()

  def send(self, op, cmd, integration_id, *args):
    """Formats and sends the requested command to the Lutron controller."""
    out_cmd = ",".join(
        (cmd, integration_id) + tuple((str(x) for x in args)))
    self._conn.send(op + out_cmd)

  def load_xml_db(self, cache_path=None):
    """Load the Lutron database from the server.

    If a locally cached copy is available, use that instead.
    """

    xml_db = None
    loaded_from = None
    processor_type = None
    processor = None
    # why don't format and parse use the same syntax!??
    # the cached file has a header that denotes which type of processor to instantiate
    header_write = "pylutron processor: {}\n"
    header_read  = "pylutron processor: {:w}"
    
    # read from cached file if it exists
    if cache_path:
      try:
        with open(cache_path, 'rb') as f:
          xml_db = f.read()
          # look for the header in the file
          p = parse.search(header_read, str(xml_db))

          # if it's there and there's a processor associated with it, use that processor
          # and fixup the xml_db to remove the header since the XML parser doesn't
          # like it there. 
          if p:
             if p.fixed[0] in Processor.Factory:
                loaded_from = 'cache'
                processor = p.fixed[0]
                xml_db = xml_db[p.spans[0][1]-1:]
      except Exception as e:
        print(e)
        pass

    # if there's no cache, try loading from the HWI database via FTP.
    # if there's nothing there, try loading from the RA2/QS URL
    #
    # this determines the Processor type to create. 
    if not loaded_from:
      try:
        _LOGGER.debug("Trying FTP for XML DB")
        import ftplib
        with ftplib.FTP(self._host, "lutron", "lutron") as ftp:
          if logging.getLogger().level == logging.DEBUG:
             ftp.set_debuglevel(2)
          ftp.set_pasv(0)
          ftp.login()
          
          # login successful, retrieve the XML database. 
          cached_file = io.BytesIO(b'0')
          ftp.cwd('proc0')
          ftp.retrbinary("RETR fullxml.dat", cached_file.write)
          loaded_from = 'FTP'
          processor = Processor.HWI

        # the xml db is in zip format, unzip it to get at the real db
        import zipfile
        with zipfile.ZipFile(cached_file) as myzip:
           with myzip.open("fulldata.dat") as myfile:
              xml_db = myfile.read()

      except Exception as e:
        _LOGGER.debug("FTP failed,trying HTTP for XML DB: %s" % e)
        import urllib.request
        url = 'http://' + self._host + '/DbXmlInfo.xml'
        with urllib.request.urlopen(url) as xmlfile:
          xml_db = xmlfile.read()
          loaded_from = 'repeater'
          processor = Processor.RA2

    # if the user asked for a specific processor, use that instead. 
    # otherwise the processor type is decided by how the database was
    # found
    if self.processor_type:
        processor = self.processor_type

    # create the processor
    _LOGGER.info("Loaded xml db from %s" % loaded_from)
    self._conn.setProcessor(Processor.Factory[processor]())

    # setup the parser based on the processor type
    parser = self._conn.processor.parser(lutron=self, xml_db_str=xml_db)

    # parse
    assert(parser.parse())     # throw our own exception
    self._areas = parser.areas
    self._name = parser.project_name

    _LOGGER.info('Found Lutron project: %s, %d areas' % (
        self._name, len(self.areas)))

    # save this for next time if a cache_path was provided
    if cache_path and loaded_from != None:
      _LOGGER.info('Saving cache file: %s' % cache_path)
      with open(cache_path, 'wb') as f:
        f.write(header_write.format(processor).encode())
        f.write(xml_db)

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

# This describes the type signature of the callback that LutronEntity
# subscribers must provide.
LutronEventHandler = Callable[['LutronEntity', Any, 'LutronEvent', Dict], None]


class LutronEvent(Enum):
  """Base class for the events LutronEntity-derived objects can produce."""
  pass


class LutronEntity(object):
  """Base class for all the Lutron objects we'd like to manage. Just holds basic
  common info we'd rather not manage repeatedly."""

  def __init__(self, lutron, name, address=None):
    """Initializes the base class with common, basic data."""
    self._lutron = lutron
    self._name = name
    self._subscribers = []
    self._address=address

  @property
  def name(self):
    """Returns the entity name (e.g. Pendant)."""
    return self._name

  @property
  def address(self):
    """Returns the address of the object. Addresses exist in legacy HWI"""
    return self._address

  def _dispatch_event(self, event: LutronEvent, params: Dict):
    """Dispatches the specified event to all the subscribers."""
    for handler, context in self._subscribers:
      handler(self, context, event, params)

  def subscribe(self, handler: LutronEventHandler, context):
    """Subscribes to events from this entity.

    handler: A callable object that takes the following arguments (in order)
             obj: the LutrongEntity object that generated the event
             context: user-supplied (to subscribe()) context object
             event: the LutronEvent that was generated.
             params: a dict of event-specific parameters

    context: User-supplied, opaque object that will be passed to handler.
    """
    self._subscribers.append((handler, context))

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
  _CMD_TYPE = 'OUTPUT'
  _ACTION_ZONE_LEVEL = 1

  class Event(LutronEvent):
    """Output events that can be generated.

    LEVEL_CHANGED: The output level has changed.
        Params:
          level: new output level (float)
    """
    LEVEL_CHANGED = 1

  def __init__(self, lutron, name, watts, output_type, integration_id, address=None):
    """Initializes the Output."""
    super(Output, self).__init__(lutron, name, address), 
    self._watts = watts
    self._output_type = output_type
    # set the level to something invalid to allow a just started system to send a command which
    # can set the level to 0. Otherwise the default value of level=0 will cause the short-circuit
    # check of the new level being the same as the old to trigger when hit with a request for
    # new level of 0
    self._level = -1.0
    self._query_waiters = _RequestHelper()
    self._integration_id = integration_id

    self._lutron.register_id(Output._CMD_TYPE, self)

  def __str__(self):
    """Returns a pretty-printed string for this object."""
    return 'Output name: "%s," watts: %d, type: "%s", id: %s, address: %s, level: %f' % (
        self._name, self._watts, self._output_type, self._integration_id, self._address, self._level)

  def __repr__(self):
    """Returns a stringified representation of this object."""
    return str({'name': self._name, 'watts': self._watts,
                'type': self._output_type, 'id': self._integration_id, 'address': self._address, 'level': self.level})

  @property
  def id(self):
    """The integration id"""
    return self._integration_id

  def handle_update(self, args):
    """Handles an event update for this object, e.g. dimmer level change."""
    _LOGGER.debug("handle_update %s -- %s" % (self._integration_id, args))
    state = int(args[0])
    if state != Output._ACTION_ZONE_LEVEL:
      return False
    level = float(args[1].strip())
    _LOGGER.debug("Updating %s(%s): s=%d l=%f" % (
        self._integration_id, self._name, state, level))
    self._level = level
    self._query_waiters.notify()
    self._dispatch_event(Output.Event.LEVEL_CHANGED, {'level': self._level})
    return True

  def __do_query_level(self):
    """Helper to perform the actual query the current dimmer level of the
    output. For pure on/off loads the result is either 0.0 or 100.0."""
    self._lutron.send(Lutron.OP_QUERY, Output._CMD_TYPE, self._integration_id,
            Output._ACTION_ZONE_LEVEL)

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
    self._lutron.send(Lutron.OP_EXECUTE, Output._CMD_TYPE, self._integration_id,
        Output._ACTION_ZONE_LEVEL, "%.2f" % new_level)
    self._level = new_level

## At some later date, we may want to also specify fade and delay times
#  def set_level(self, new_level, fade_time, delay):
#    self._lutron.send(Lutron.OP_EXECUTE, Output._CMD_TYPE,
#        Output._ACTION_ZONE_LEVEL, new_level, fade_time, delay)

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


class KeypadComponent(LutronEntity):
  """Base class for a keypad component such as a button, or an LED."""

  def __init__(self, lutron, keypad, name, num, component_num):
    """Initializes the base keypad component class."""
    super(KeypadComponent, self).__init__(lutron, name)
    self._keypad = keypad
    self._num = num
    self._component_num = component_num

  @property
  def number(self):
    """Returns the user-friendly number of this component (e.g. Button 1,
    or LED 1."""
    return self._num

  @property
  def component_number(self):
    """Return the lutron component number, which is referenced in commands and
    events. This is different from KeypadComponent.number because this property
    is only used for interfacing with the controller."""
    return self._component_num

  def handle_update(self, action, params):
    """Handle the specified action on this component."""
    _LOGGER.debug('Keypad: "%s" Handling "%s" Action: %s Params: %s"' % (
                  self._keypad.name, self.name, action, params))
    return False


class Button(KeypadComponent):
  """This object represents a keypad button that we can trigger and handle
  events for (button presses)."""
  _ACTION_PRESS = 3
  _ACTION_RELEASE = 4

  class Event(LutronEvent):
    """Button events that can be generated.

    PRESSED: The button has been pressed.
        Params: None

    RELEASED: The button has been released. Not all buttons
              generate this event.
        Params: None
    """
    PRESSED = 1
    RELEASED = 2

  def __init__(self, lutron, keypad, name, num, button_type, direction):
    """Initializes the Button class."""
    super(Button, self).__init__(lutron, keypad, name, num, num)
    self._button_type = button_type
    self._direction = direction

  def __str__(self):
    """Pretty printed string value of the Button object."""
    return 'Button name: "%s", num: %d, type: "%s"' % (
        self.name, self.number, self._button_type)

  def __repr__(self):
    """String representation of the Button object."""
    return str({'name': self.name, 'num': self.number,
               'type': self._button_type, 'direction': self._direction})

  @property
  def button_type(self):
    """Returns the button type (Toggle, MasterRaiseLower, etc.)."""
    return self._button_type

  def press(self):
    """Triggers a simulated button press to the Keypad."""
    self._lutron.send(Lutron.OP_EXECUTE, Keypad._CMD_TYPE, self._keypad.id,
                      self.component_number, Button._ACTION_PRESS)

  def release(self):
    """Triggers a simulated button release to the Keypad."""
    self._lutron.send(Lutron.OP_EXECUTE, Keypad._CMD_TYPE, self._keypad.id,
                      self.component_number, Button._ACTION_RELEASE)

  def tap(self):
    """Triggers a simulated button tap to the Keypad."""
    self.press()
    self.release()

  def handle_update(self, action, params):
    """Handle the specified action on this component."""
    _LOGGER.debug('Keypad: "%s" %s Action: %s Params: %s"' % (
                  self._keypad.name, self, action, params))
    ev_map = {
        Button._ACTION_PRESS: Button.Event.PRESSED,
        Button._ACTION_RELEASE: Button.Event.RELEASED
    }
    if action not in ev_map:
      _LOGGER.debug("Unknown action %d for button %d in keypad %s" % (
          action, self.number, self._keypad.name))
      return False
    self._dispatch_event(ev_map[action], {})
    return True


class Led(KeypadComponent):
  """This object represents a keypad LED that we can turn on/off and
  handle events for (led toggled by scenes)."""
  _ACTION_LED_STATE = 9

  class Event(LutronEvent):
    """Led events that can be generated.

    STATE_CHANGED: The button has been pressed.
        Params:
          state: The boolean value of the new LED state.
    """
    STATE_CHANGED = 1

  def __init__(self, lutron, keypad, name, led_num, component_num):
    """Initializes the Keypad LED class."""
    super(Led, self).__init__(lutron, keypad, name, led_num, component_num)
    self._state = False
    self._query_waiters = _RequestHelper()

  def __str__(self):
    """Pretty printed string value of the Led object."""
    return 'LED keypad: "%s", name: "%s", num: %d, component_num: %d"' % (
        self._keypad.name, self.name, self.number, self.component_number)

  def __repr__(self):
    """String representation of the Led object."""
    return str({'keypad': self._keypad, 'name': self.name,
                'num': self.number, 'component_num': self.component_number})

  def __do_query_state(self):
    """Helper to perform the actual query for the current LED state."""
    self._lutron.send(Lutron.OP_QUERY, Keypad._CMD_TYPE, self._keypad.id,
            self.component_number, Led._ACTION_LED_STATE)

  @property
  def last_state(self):
    """Returns last cached value of the LED state, no query is performed."""
    return self._state

  @property
  def state(self):
    """Returns the current LED state by querying the remote controller."""
    ev = self._query_waiters.request(self.__do_query_state)
    ev.wait(1.0)
    return self._state

  @state.setter
  def state(self, new_state: bool):
    """Sets the new led state.

    new_state: bool
    """
    self._lutron.send(Lutron.OP_EXECUTE, Keypad._CMD_TYPE, self._keypad.id,
                      self.component_number, Led._ACTION_LED_STATE,
                      int(new_state))
    self._state = new_state

  def handle_update(self, action, params):
    """Handle the specified action on this component."""
    _LOGGER.debug('Keypad: "%s" %s Action: %s Params: %s"' % (
                  self._keypad.name, self, action, params))
    if action != Led._ACTION_LED_STATE:
      _LOGGER.debug("Unknown action %d for led %d in keypad %s" % (
          action, self.number, self._keypad.name))
      return False
    elif len(params) < 1:
      _LOGGER.debug("Unknown params %s (action %d on led %d in keypad %s)" % (
          params, action, self.number, self._keypad.name))
      return False
    self._state = bool(params[0])
    self._query_waiters.notify()
    self._dispatch_event(Led.Event.STATE_CHANGED, {'state': self._state})
    return True


class Keypad(LutronEntity):
  """Object representing a Lutron keypad.

  Currently we don't really do much with it except handle the events
  (and drop them on the floor).
  """
  _CMD_TYPE = 'DEVICE'

  def __init__(self, lutron, name, keypad_type, location, integration_id, address=None):
    """Initializes the Keypad object."""
    super(Keypad, self).__init__(lutron, name, address)
    self._buttons = []
    self._leds = []
    self._components = {}
    self._location = location
    self._integration_id = integration_id
    self._type = keypad_type

    self._lutron.register_id(Keypad._CMD_TYPE, self)

  def add_button(self, button):
    """Adds a button that's part of this keypad. We'll use this to
    dispatch button events."""
    self._buttons.append(button)
    self._components[button.component_number] = button

  def add_led(self, led):
    """Add an LED that's part of this keypad."""
    self._leds.append(led)
    self._components[led.component_number] = led

  @property
  def id(self):
    """The integration id"""
    return self._integration_id

  @property
  def name(self):
    """Returns the name of this keypad"""
    return self._name

  @property
  def type(self):
    """Returns the keypad type"""
    return self._type

  @property
  def location(self):
    """Returns the location in which the keypad is installed"""
    return self._location

  @property
  def buttons(self):
    """Return a tuple of buttons for this keypad."""
    return tuple(button for button in self._buttons)

  @property
  def leds(self):
    """Return a tuple of leds for this keypad."""
    return tuple(led for led in self._leds)

  def handle_update(self, args):
    """The callback invoked by the main event loop if there's an event from this keypad."""
    component = int(args[0])
    action = int(args[1])
    params = [int(x) for x in args[2:]]
    _LOGGER.debug("Updating %d(%s): c=%d a=%d params=%s" % (
        self._integration_id, self._name, component, action, params))
    if component in self._components:
      return self._components[component].handle_update(action, params)
    return False

  def __str__(self):
    """Returns a pretty-printed string for this object."""
    return 'Keypad name: "%s", location: %s, id: %s, type: %s, address: %s\n\t\t%s\n\t\t%s' % (
        self._name, self._location, self._integration_id, self._type, self._address,
        "\n\t\t".join([str(o) for o in self._buttons]),
        "\n\t\t".join([str(o) for o in self._leds])
      )

class PowerSource(Enum):
  """Enum values representing power source, reported by queries to
  battery-powered devices."""
  
  # Values from ?HELP,?DEVICE,22
  UNKNOWN = 0
  BATTERY = 1
  EXTERNAL = 2

  
class BatteryStatus(Enum):
  """Enum values representing battery state, reported by queries to
  battery-powered devices."""
  
  # Values from ?HELP,?DEVICE,22 don't match the documentation, using what's in the doc.
  #?HELP says:
  # <0-NOT BATTERY POWERED, 1-DEVICE_BATTERY_STATUS_UNKNOWN, 2-DEVICE_BATTERY_STATUS_GOOD, 3-DEVICE_BATTERY_STATUS_LOW, 4-DEVICE_STATUS_MIA>5-DEVICE_STATUS_NOT_ACTIVATED>
  NORMAL = 1
  LOW = 2
  OTHER = 3  # not sure what this value means


class MotionSensor(LutronEntity):
  """Placeholder class for the motion sensor device.
  Although sensors are represented in the XML, all of the protocol
  happens at the OccupancyGroup level. To read the state of an area,
  use area.occupancy_group.
  """

  _CMD_TYPE = 'DEVICE'

  _ACTION_BATTERY_STATUS = 22

  class Event(LutronEvent):
    """MotionSensor events that can be generated.
    STATUS_CHANGED: Battery status changed
        Params:
          power: PowerSource
          battery: BatteryStatus
    Note that motion events are reported by OccupancyGroup, not individual
    MotionSensors.
    """
    STATUS_CHANGED = 1

  def __init__(self, lutron, name, integration_id):
    """Initializes the motion sensor object."""
    super(MotionSensor, self).__init__(lutron, name)
    self._integration_id = integration_id
    self._battery = None
    self._power = None
    self._lutron.register_id(MotionSensor._CMD_TYPE, self)
    self._query_waiters = _RequestHelper()
    self._last_update = None

  @property
  def id(self):
    """The integration id"""
    return self._integration_id

  def __str__(self):
    """Returns a pretty-printed string for this object."""
    return 'MotionSensor {}, Id: {}, Battery: {}, Power: {}'.format(
        self.name, self.id, self.battery_status, self.power_source)

  def __repr__(self):
    """String representation of the MotionSensor object."""
    return str({'motion_sensor_name': self.name, 'id': self.id,
                'battery' : self.battery_status,
                'power' : self.power_source})

  @property
  def _update_age(self):
    """Returns the time of the last poll in seconds."""
    if self._last_update is None:
      return 1e6
    else:
      return time.time() - self._last_update

  @property
  def battery_status(self):
    """Returns the current BatteryStatus."""
    # Battery status won't change frequently but can't be retrieved for MONITORING.
    # So rate limit queries to once an hour.
    if self._update_age > 3600.0:
      ev = self._query_waiters.request(self._do_query_battery)
      ev.wait(1.0)
    return self._battery

  @property
  def power_source(self):
    """Returns the current PowerSource."""
    self.battery_status  # retrieved by the same query
    return self._power

  def _do_query_battery(self):
    """Helper to perform the query for the current BatteryStatus."""
    component_num = 1  # doesn't seem to matter
    return self._lutron.send(Lutron.OP_QUERY, MotionSensor._CMD_TYPE, self._integration_id,
                             component_num, MotionSensor._ACTION_BATTERY_STATUS)

  def handle_update(self, args):
    """Handle the specified action on this component."""
    if len(args) != 6:
      _LOGGER.debug('Wrong number of args for MotionSensor update {}'.format(len(args)))
      return False
    _, action, _, power, battery, _ = args
    action = int(action)
    if action != MotionSensor._ACTION_BATTERY_STATUS:
      _LOGGER.debug("Unknown action %d for motion sensor {}".format(self.name))
      return False
    self._power = PowerSource(int(power))
    self._battery = BatteryStatus(int(battery))
    self._last_update = time.time()
    self._query_waiters.notify()
    self._dispatch_event(
      MotionSensor.Event.STATUS_CHANGED, {'power' : self._power, 'battery': self._battery})
    return True


class OccupancyGroup(LutronEntity):
  """Represents one or more occupancy/vacancy sensors grouped into an Area."""
  _CMD_TYPE = 'GROUP'
  _ACTION_STATE = 3

  class State(Enum):
    """Possible states of an OccupancyGroup."""
    OCCUPIED = 3
    VACANT = 4
    UNKNOWN = 255

  class Event(LutronEvent):
    """OccupancyGroup event that can be generated.
    OCCUPANCY: Occupancy state has changed.
        Params:
          state: an OccupancyGroup.State
    """
    OCCUPANCY = 1

  def __init__(self, lutron, area):
    super(OccupancyGroup, self).__init__(lutron, 'Occ {}'.format(area.name))
    self._area = area
    self._integration_id = area.id
    self._state = None
    self._lutron.register_id(OccupancyGroup._CMD_TYPE, self)
    self._query_waiters = _RequestHelper()

  @property
  def id(self):
    """The integration id"""
    return self._integration_id

  @property
  def name(self):
    """Return the name of this OccupancyGroup, which is 'Occ' plus the name of the area."""
    return 'Occ {}'.format(self._area.name)

  @property
  def state(self):
    """Returns the current occupancy state."""
    # Poll for the first request.
    if self._state == None:
      ev = self._query_waiters.request(self._do_query_state)
      ev.wait(1.0)
    return self._state

  def __str__(self):
    """Returns a pretty-printed string for this object."""
    return 'OccupancyGroup for Area "{}" Id: {} State: {}'.format(
        self._area.name, self.id, self.state.name)

  def __repr__(self):
    """Returns a stringified representation of this object."""
    return str({'area_name' : self.area.name,
                'id' : self.id,
                'state' : self.state})

  def _do_query_state(self):
    """Helper to perform the actual query for the current OccupancyGroup state."""
    return self._lutron.send(Lutron.OP_QUERY, OccupancyGroup._CMD_TYPE, self._integration_id,
                             OccupancyGroup._ACTION_STATE)

  def handle_update(self, args):
    """Handles an event update for this object, e.g. occupancy state change."""
    action = int(args[0])
    if action != OccupancyGroup._ACTION_STATE or len(args) != 2:
      return False
    try:
      self._state = OccupancyGroup.State(int(args[1]))
    except ValueError:
      self._state = OccupancyGroup.State.UNKNOWN
    self._query_waiters.notify()
    self._dispatch_event(OccupancyGroup.Event.OCCUPANCY, {'state': self._state})
    return True


class Area(object):
  """An area (i.e. a room) that contains devices/outputs/etc."""
  def __init__(self, lutron, name, integration_id, occupancy_group_id):
    self._lutron = lutron
    self._name = name
    self._integration_id = integration_id
    self._occupancy_group_id = occupancy_group_id
    self._occupancy_group = None
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
    if not self._occupancy_group:
      self._occupancy_group = OccupancyGroup(self._lutron, self)

  def __str__(self):
    """Returns a pretty-printed string for this object."""
    return 'Area name: "%s", occupancy_group_id: %s, id: %d\n\t%s\n\t%s' % (
        self._name, self._occupancy_group_id, self._integration_id,
        "\n\t".join([str(o) for o in self._outputs]),
        "\n\t".join([str(o) for o in self._keypads])
      )

  def __repr__(self):
    """Returns a stringified representation of this object."""
    return str({'name': self._name,
                'occupancy_group_id': self._occupancy_group_id, 'id': self._integration_id,
                'outputs': self._outputs, 'keypads': self._keypads})

  @property
  def name(self):
    """Returns the name of this area."""
    return self._name

  @property
  def id(self):
    """The integration id of the area."""
    return self._integration_id

  @property
  def occupancy_group(self):
    """Returns the OccupancyGroup for this area, or None."""
    return self._occupancy_group

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
