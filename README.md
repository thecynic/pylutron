pylutron
=====
A simple Python library for controlling a Lutron RadioRA 2 system with a Main
Repeater.

Installation
------------
You can get the code from `https://github.com/thecynic/pylutron`

Example
-------
    import pylutron

    rra2 = pylutron.Lutron("192.168.0.x", "lutron", "integration")
    rra2.load_xml_db()
    rra2.connect()


License
-------
This code is released under the MIT license.
