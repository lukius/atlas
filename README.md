atlas
=====

Wireshark dissector for ATLAS TDAQ protocol

## Compilation

  * The Makefile provided compiles the dissector for x64 platforms.

### Requirements

  * wireshark-dev
  * glib-2.0

## Installation

  * Copy the compiled plugin shared object file (packet-atlas.so) to the global plugins directory of Wireshark.
  * This directory can be found at Help --> About Wireshark --> Folders.

## ToDo List

  * Multi-packet processing. This might be addressed by writing Lua post-dissectors or other techniques beyond the scope of this dissector.
  * Improve how the dissector is hooked into Wireshark.
    * Currently, it is basically replacing the standard TCP dissector, since it uses the `ip.proto` field when it is set to 6.
    * TCP port numbers can be used, but in order to do this it is essential to define one (or possibly many as well) standard, well-known ports for DCM-ROS communication.

