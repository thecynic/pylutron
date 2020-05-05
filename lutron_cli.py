#!/usr/bin/env python3
import pylutron
import cmd2
import sys
import time
import argparse
import re
import logging
import time

# Change these to match the site
default_controller = "192.168.111.123"
default_user = "ipad"
default_password = "ipad"

# create the top-level parser for the alternate command
# The alternate command doesn't provide its own help flag
list_parser = argparse.ArgumentParser()
list_subparsers = list_parser.add_subparsers(title='subcommands')
light_parser = argparse.ArgumentParser()
button_parser = argparse.ArgumentParser()

class lutron(cmd2.Cmd):
    def __init__(self, controller, user, password):
        cmd2.Cmd.__init__(self)
        self.prompt = "pylutron> "
        self.self_in_py = True
        self.default_category = "Python cmd2 built-ins"
        
#        self._l = pylutron.Lutron(controller, user, password, pylutron.Processor.QS)
#        self._db = self._l.load_xml_db("/tmp/cached_xml_db")
        self._l = pylutron.Lutron(controller, user, password)
        self._db = self._l.load_xml_db()

        self._l.connect()

        # table for list commands. allows listing of areas, keypads, switches, lights, and fans.
        # default lists only the name, optional --full argument lists all attributes
        # keypads can take optional --button argument to list the buttons associated with the keypad
        # all devices can take an optional regex filter
        devices = [{"cmd":"areas",    "func":self._list_areas},
                   {"cmd":"keypads",  "func":self._list_keypads, "args":('-b', '--button')},
                   {"cmd":"switches", "func":self._list_switches},
                   {"cmd":"lights",   "func":self._list_lights},
                   {"cmd":"fans",     "func":self._list_fans} ]
        for d in devices:
            subparser = list_subparsers.add_parser(d["cmd"])
            subparser.set_defaults(func=d["func"])
            subparser.add_argument('filter', nargs='?')
            subparser.add_argument('-f', '--full', action='store_true')

            if "args" in d:
                subparser.add_argument(d['args'][0], d['args'][1], nargs='?', const='.*', default=None)

        light_parser.add_argument('filter', nargs='?', const='.*', default=None)
        lsp = light_parser.add_subparsers()
        sp = lsp.add_parser("on")
        sp.set_defaults(func=self._lights_on)
        sp.add_argument('level', nargs='?', default="100")

        sp = lsp.add_parser("off")
        sp.set_defaults(func=self._lights_off)

        button_parser.add_argument('keypad')
        button_parser.add_argument('button')

    
    @cmd2.with_category("PyLutron")
    @cmd2.with_argparser(list_parser)
    def do_list(self, args):
        """List all the devices in the controller"""

        if filter in args and args.filter:
            try:
                re.compile(args.filter)
            except:
                self.poutput("Bad regular expression for match filter \"%s\". Try again." % args.filter)
                return

        if 'func' in args:
            self.poutput("\n".join([s for (d, s) in args.func(args)]))
            return
        
        self.poutput("\n".join([str(a) for a in self._l.areas]))

    @cmd2.with_category("PyLutron")
    @cmd2.with_argparser(light_parser)
    def do_lights(self, args):
        """Turn a light on/off"""

        # find the lights requested by the filter
        args.full=False
        lights = self._list_lights(args)

        # make sure there's at least one
        if not lights:
            self.poutput("No lights matching \"%s\" found" % args.filter)
            return

        # turn them on/off
        if 'func' in args:
            for (light, name) in lights:
                args.func(light, args)
            return

        # if there's on on/off requested, print the light with it's level
        for (light, name) in lights:
            self.poutput("name: {}, level: {}".format(name, light.level))

    def _lights_on(self, light, args):
        """Turn a light on to a specific level"""
        light.level = float(args.level)

    def _lights_off(self, light, args):
        """Turn a light off, i.e. level = 0"""
        light.level = 0.0

    @cmd2.with_category("PyLutron")
    @cmd2.with_argparser(button_parser)
    def do_press(self, args):
        """Press a button"""

        # find the buttons requested by the filter
        args.full=False
        args.filter=args.keypad
        keypads = self._list_keypads(args)

        # make sure there's at least one
        if not keypads:
            self.poutput("No keypad matching \"%s\" found" % args.filter)
            return

        for (kp, name) in keypads:
            buttons = self.list_buttons(args, kp, True)
            for b in buttons:
                b.press()
            
    def _list_areas(self, args):
        """List the areas in the controller"""
        format_str = "{0!s}" if args.full else "{0.name}"

        filter_regex = r'(?i:%s)' % args.filter if args.filter else r'.*'

        return [(a,format_str.format(a)) for a in self._l.areas if re.match(filter_regex, a.name)]

    def default_more_cb(self, *args, **kwargs):
        return True
    
    def _list_helper(self, args, attr, kind, format_str_pre="", format_str_post="", more_cb=default_more_cb):
        """Returns a list of (obj, str) tuples filtered by args.filter regex. The format of the str is determined
        by args.full."""
        format_str = "{0!s}" if args.full else "{1[0]}"
        format_str = format_str_pre + format_str + format_str_post

        filter_regex = r'(?i:%s)' % args.filter if args.filter else r'.*'
            
        out = ""
        devices = []
        for a in self._l.areas:
            devices.extend([(a,d) for d in getattr(a,attr) if re.match(kind, d.type) and re.match(filter_regex, d.name)])

        return [(d,format_str.format(d, str(d).split(","), more_cb(args,d))) for (a,d) in devices if more_cb(args,d)]

    def list_buttons(self, args, keypad, obj=False):
        if args.button:
            try:
                regex_str = r"(?i:%s)" % args.button
                regex = re.compile(regex_str)
                if obj:
                    buttons = [b for b in keypad.buttons if regex.match(b.name)]
                else:
                    buttons = "\n\t".join([ str(b) for b in keypad.buttons if regex.match(b.name)])
                if buttons == '\n\t': 
                    buttons = []
            except:
                buttons = "Bad button match filter \"%s\". Try again." % args.button

        return buttons

    def _list_keypads(self, args):
        """List the areas in the controller"""

        if args.button:
            return self._list_helper(args, "keypads", r'KEYPAD', "", "\n\t{2}", self.list_buttons)
        else:
            return self._list_helper(args, "keypads", r'KEYPAD')

    def _list_switches(self, args):
        """List the areas in the controller"""
        return self._list_helper(args, "keypads", r'DIMMER/SWITCH')

    def _list_lights(self, args):
        """List the lights in the controller"""
        return self._list_helper(args, "outputs", r'DIMMER')

    def _list_fans(self, args):
        """List the areas in the controller"""
        return self._list_helper(args, "outputs", r'FAN')

if __name__ == '__main__':
    cmdline = argparse.ArgumentParser(description="pylutron CLI")
    cmdline.add_argument('-c', '--controller', default=default_controller)
    cmdline.add_argument('-u', '--user', default=default_user)
    cmdline.add_argument('-p', '--password', default=default_password)
    cmdline.add_argument('-d', '--debug', action='store_true')

    # only consume the connection args, if there are other cmd line args assume 
    # those are commands
    args, left = cmdline.parse_known_args()
    sys.argv = sys.argv[:1]+left

    if args.debug:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    # create the lutron class
    app = lutron(args.controller, args.user, args.password)

    # Note, the connection to the processor will retry forever, so this check
    # is a bit superflous
    if not app._l.connected:
        sys.exit()

    # either run a command or enter the interactive loop
    if len(sys.argv) > 1:
       app.onecmd_plus_hooks(" ".join(sys.argv[1:]))
    else:
      sys.exit(app.cmdloop())
  
