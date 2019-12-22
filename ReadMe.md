# Requirements

Hardware:

- PC with SDIO host (For example Raspberry Pi, Beaglebone, etc)

Software:

- Linux
- Python3


# Setup

Install python3-venv package.
In this folder execute following commands:

    python3 -m venv venv
    ./venv/bin/pip install -r requirements.txt

That's it.


# Usage

In general code should be self-explanatory. But there is a small built in help, just run 

    ./MstarUtil.py -h


## Verify update file

    ./MstarUtil.py validate ../MstarUpgrade.bin

It will parse update header and dump partitions and actions.


## Write update file to EMMC

Important notice: your must have sdio host controller to access emmc boot partitions and service data. Application will fail if it's not present.

    ./MstarUtil.py write ../MstarUpgrade.bin /dev/mmcblk2


# Raspberry Pi SDIO

Pinout: https://pinout.xyz/pinout/sdio

Load device tree overlay for 4-bit wide bus:

    dtoverlay sdio

Also keep in mind that you can access EMMC card with only 1 data line.
Load device tree overlay for 1-bit wide bus:

    dtoverlay sdio bus_width=1


After that command you'll see new devices:
/dev/mmcblk2        # main storage
/dev/mmcblk2boot0   # main boot partition
/dev/mmcblk2boot1   # second boot partition, normally not used
/dev/mmcblk2rpmb    # rpmb special device

mmc-utils can provide detailed information for connected flash. 


# Wiring

Keep in mind that wires must have same length.