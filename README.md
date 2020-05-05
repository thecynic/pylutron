pylutron
=====
A simple Python library for controlling a Lutron RadioRA 2 system with a Main
Repeater.

Installation
------------
You can get the code from `https://github.com/thecynic/pylutron`

API Example
-----------
    import pylutron

    rra2 = pylutron.Lutron("192.168.0.x", "lutron", "integration")
    rra2.load_xml_db()
    rra2.connect()

CLI Example
-----------

Interactive CLI:

    ./lutron_cli.py -c mycontroller -u myuser -p mypassword
    pylutron> help
    pylutron> list
    pylutron> light my_light on 75
    pylutron> list keypads -f
    pylutron> press my_k m

Non-interactive Scripting:

    ./lutron_cli.py -c mycontroller -u myuser -p mypassword light my_light on 75

All commands take a filter, which is a case insensitive regex filter. Without
wildcards, the filter matches at the start of the string. For example,

    pylutron> list areas a

Will match all areas that start with 'a'. To match all areas with an 'a', 
the regex will look like:

    pylutron> list areas .*a.*

Most commands have a -h to get per command help. Most of the list commands
have a -f to see more details. This is especially helpful with Keypads
to see which Buttons they contain. 

License
-------
This code is released under the MIT license.
