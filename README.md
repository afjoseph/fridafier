# Fridafier

Automatically insert Frida gadget 

This tool was developed mainly to automatically insert [Frida Gadget](https://frida.re/docs/gadget/) inside APKs.

## Usage

    $ poetry install
    $ poetry run python 3 fridafier --init
    $ poetry run python 3 fridafier --apk my.apk --script log.js
    # Where log.js can be any Frida agent, like this one

        Java.perform(function(){
            var Log = Java.use('android.util.Log');
            Log.w("FRIDAGADGET", "Hello World");
        });
