import asyncio # This library is needed for newer versions of python. It basically allows background tasks
import pyshark # This is the cool python wireshark analyzer

# Turns out pyshark relies on a feature of python that was removed in the newer versions so we have to force it back in.
# Note: This was written using python version 3.14

#--------------------------------------------------------------------------------------------------------------
#                                   Dummy class to make pyshark work properly
#--------------------------------------------------------------------------------------------------------------

class DummyWatcher:
    def attach_loop(self, loop): pass
    def close(self): pass
    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): pass

if not hasattr(asyncio, 'SafeChildWatcher'):
    asyncio.SafeChildWatcher = DummyWatcher

if not hasattr(asyncio, 'set_child_watcher'):
    asyncio.set_child_watcher = lambda watcher: None

if not hasattr(asyncio, 'get_child_watcher'):
    asyncio.get_child_watcher = lambda: DummyWatcher()

#--------------------------------------------------------------------------------------------------------------
#                                       Actual python code starts here:
#--------------------------------------------------------------------------------------------------------------

# Python code analyzer for wireshark capture data parsing

# Event loop startup
asyncio.set_event_loop(asyncio.new_event_loop())

# Wireshark capture file:
WIRESHARK_CAPTURE = 'Wireshark_Packet_Capture_23Mar2026.pcapng'

print(f"loading {WIRESHARK_CAPTURE}")

# Try loop to make sure the file loads properly
try:
    # Load the wireshark capture file
    capture = pyshark.FileCapture(WIRESHARK_CAPTURE)

    # Testing with 1 packet to make sure it works
    first_packet = capture[0]

    # Print out results of loading the packet
    print("\n Packet successfully loaded!")
    print(f"Protocol: {first_packet.highest_layer}")
    print(f"Length: {first_packet.length} bytes")

    # Gotta close the packet capture so we can free up memory
    capture.close()

# Error results in case the file can't be loaded for some reason
except FileNotFoundError:
    print(f"ERROR: File not found")
except Exception as e:
    print(f"An error occurred: {e}")