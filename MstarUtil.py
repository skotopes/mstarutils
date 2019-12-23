#!venv/bin/python

import coloredlogs 
import logging
import argparse
import os

class Main:
    def __init__(self):
        # Logging
        self.logger = logging.getLogger("MstarUtil")
        # Argument parser
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-d", "--debug", action='store_true', help="Debug")
        self.parser.add_argument("-v", "--verbose", action='store_true', help="Verbose")
        self.subparsers = self.parser.add_subparsers(help='sub-command help')
        self.parser_validate = self.subparsers.add_parser('validate', help='Validate upgrade file structure')
        self.parser_validate.add_argument("mstar", help="Path to MstarUpgrade.bin file")
        self.parser_validate.set_defaults(func=self.validate)

        self.parser_write = self.subparsers.add_parser('write', help='Write upgrade to emmc')
        self.parser_write.add_argument("mstar", help="Path to MstarUpgrade.bin file")
        self.parser_write.add_argument("emmc", help="Path to EMMC disk")
        self.parser_write.set_defaults(func=self.write)
        # Upgrade data
        self.partitions = {}
        self.boot = None
        self.writes = []

    def __call__(self):
        # Parse args
        self.args = self.parser.parse_args()
        if self.args.debug:
            coloredlogs.install(level='DEBUG')
            self.logger.info("Debug output is enabled")
        else:
            coloredlogs.install(level='INFO', logger=self.logger)
        if not hasattr(self.args, 'func'):
            self.parser.error('Choose something to do')
        try:
            self.args.func()
        except Exception as e:
            self.logger.exception(e)
            exit(1)

    def addPartition(self, data):
        if len(data) != 2:
            raise Exception("Invalid partition data, args count %s != 2", len(data))
        name = data[0].decode()
        address = int(data[1], base=16)
        self.partitions[name] = {
            "name": name,
            "address": address
        }

    def addWritePartition(self, source, destination):
        # Initial Validation 
        if len(source) != 4:
            raise Exception("Invalid source data, args count %s != 4", len(source))
        if len(destination) not in (3,4):
            raise Exception("Invalid destination data, args count %s != 4", len(destination))
        # Parse
        source_address = int(source[2], base=16)
        source_size = int(source[3], base=16)
        destination_name = destination[1].decode()
        destination_size = int(destination[2], base=16)
        if len(destination) == 4: 
            destination_empty_skip = int(destination[3])
        else:
            destination_empty_skip = 0
        # Final Validation
        if source_size != destination_size:
            raise Exception("Write partition commands conflict: source_size != destination_size")
        # Add to writes list
        self.writes.append({
            "source_address": source_address,
            "source_size": source_size,
            "destination_name": destination_name,
            "destination_size": destination_size,
            "destination_empty_skip": destination_empty_skip
        })

    def addWriteBoot(self, source, destination):
        if len(source) != 4:
            raise Exception("Invalid source data, args count %s != 4", len(source))
        if len(destination) not in (3,4):
            raise Exception("Invalid destination data, args count %s != 4", len(destination))
        source_address = int(source[2], base=16)
        source_size = int(source[3], base=16)
        self.boot = {
            "source_address": source_address,
            "source_size": source_size
        }

    def parseUpgradeScript(self):
        self.logger.info("Parsing upgrade script")

        self.logger.debug("Reading first 16384 bytes of mstar")
        upgrade_script = self.mstar.read(16384)
        upgrade_script_end = upgrade_script.find(b"% <-this is end of file symbol")
        if upgrade_script_end == -1:
            raise Exception("Unable to find Upgrade Script end. Invalid file or unknown file format.")
        self.logger.debug("End symbols found at %s, stripping rest", upgrade_script_end)
        upgrade_script = upgrade_script[:upgrade_script_end]

        self.logger.debug("Parsing content")
        filepartload_tmp = None
        unknown_command_flag = False
        for upgrade_script_line in upgrade_script.splitlines():
            self.logger.debug(upgrade_script_line)
            if upgrade_script_line.startswith(b"mmc slc"):
                self.logger.warning("`mmc slc` - is not supported")
            elif upgrade_script_line.startswith(b"mmc rmgpt"):
                self.logger.warning("`mmc rmgpt` - is not supported")
            elif upgrade_script_line.startswith(b"mmc erase.p"):
                self.logger.warning("`mmc erase.p` - is not supported")
            elif upgrade_script_line.startswith(b"filepartload"):
                if filepartload_tmp:
                    raise Exception("Malformed upgrade script: `filepartload` was used without `mmc write.p`")
                filepartload_tmp = upgrade_script_line[len(b"filepartload "):].split(b" ", 3)
            elif upgrade_script_line.startswith(b"mmc write.p"):
                if not filepartload_tmp:
                    raise Exception("Malformed upgrade script: `mmc write.p` was used without `filepartload`")
                mmc_write_tmp = upgrade_script_line[len(b"mmc write.p "):].split(b" ", 3)
                self.addWritePartition(filepartload_tmp, mmc_write_tmp)
                filepartload_tmp = None
            elif upgrade_script_line.startswith(b"mmc write.boot"):
                mmc_write_tmp = upgrade_script_line[len(b"mmc write.boot "):].split(b" ", 4)
                self.addWriteBoot(filepartload_tmp, mmc_write_tmp)
                filepartload_tmp = None
            elif upgrade_script_line.startswith(b"store_secure_info"):
                self.logger.warning("`store_secure_info` - is not supported, however `filepartload` tmp cleared")
                filepartload_tmp = None
            elif upgrade_script_line.startswith(b"store_nuttx_config"):
                self.logger.warning("`store_nuttx_config` - is not supported, however `filepartload` tmp cleared")
                filepartload_tmp = None
            elif upgrade_script_line.startswith(b"mmc unlzo"):
                self.logger.warning("`mmc unlzo` - is not supported, however `filepartload` tmp cleared")
                filepartload_tmp = None
            elif upgrade_script_line.startswith(b"mmc create"):
                self.addPartition(upgrade_script_line[len(b"mmc create "):].split(b" "))
            elif upgrade_script_line.startswith(b"setenv"):
                self.logger.warning("`setenv` - is not supported")
            elif upgrade_script_line.startswith(b"saveenv"):
                self.logger.warning("`saveenv` - is not supported")
            elif upgrade_script_line.startswith(b"sync_mmap"):
                self.logger.warning("`sync_mmap` - is not supported")
            elif upgrade_script_line.startswith(b"printenv"):
                self.logger.warning("`printenv` - is not supported")
            else:
                self.logger.error("Unknown command: %s", upgrade_script_line);
                unknown_command_flag = True
        if unknown_command_flag:
            self.logger.error("Not all upgrade script commands are parsed")
            if input("Type `ok` to continue: ").lower() != 'ok':
                raise Exception("Unknown command in upgrade script")

    def dumpUpgradeScriptData(self):
        self.logger.info("")
        self.logger.info(f"{' Partition map ':-^29}")
        self.logger.info(f"| {'Name':12} | {'Address':>10} |")
        self.logger.info(f"{'':-^29}")
        for partition in self.partitions.values():
            self.logger.info(f"| {partition['name']:12} | {partition['address']:10x} |")
        self.logger.info("")
        self.logger.info(f"{' Write operations ':-^48}")
        self.logger.info(f"| {'Name':12} | {'Source':>10} | {'Size':>8} | {'Skip':>5} |")
        self.logger.info(f"{'':-^48}")
        for write in self.writes:
            self.logger.info(
                f"| {write['destination_name']:12} | {write['source_address']:10x} | {write['source_size']:8x} | {write['destination_empty_skip']:5} |"
            )
        self.logger.info("")
        self.logger.info(f"{' Boot ':-^48}")
        if self.boot:
            self.logger.info(f"Boot source address {self.boot['source_address']}, size {self.boot['source_size']}")
        else:
            self.logger.info("Boot is not present")
        self.logger.info("")

    def writeBoot(self):
        self.logger.info("Writing bootloader")

        self.logger.info(f"Opening boot0 disk: {self.args.emmc}boot0")
        sys_disk_forcero = "/sys/block/{}boot0/force_ro".format(self.args.emmc.replace("/dev/",""))
        if os.system(f"echo 0 > {sys_disk_forcero}") != 0:
            raise Exception("Unable to unlock boot0")
        disk = open(f"{self.args.emmc}boot0", "wb")

        self.logger.info(f"Seeking mstarfile to {self.boot['source_address']}")
        self.mstar.seek(self.boot['source_address'])

        self.logger.info(f"Writing {self.boot['source_size']}")
        bytes_left = self.boot['source_size']
        while bytes_left > 0:
            chunk_size = bytes_left if bytes_left > 1024 else 1024
            chunk_data = self.mstar.read(chunk_size)
            if len(chunk_data) != chunk_size:
                raise Exception("Read source failed, read size != chunk size")
            write_size = disk.write(chunk_data)
            if write_size != chunk_size:
                raise Exception("Write destination failed, write size != chunk size")
            bytes_left -= chunk_size

        self.logger.info("Closing boot disk")
        disk.close()

    def writePartitions(self):
        self.logger.info("Writing paritions")

        self.logger.info(f"Opening disk: {self.args.emmc}")
        disk = open("{self.args.emmc}", "wb")

        for write in self.writes:
            if not write['destination_name'] in self.partitions.keys():
                self.logger.warning(f"Unknown patition: {write['destination_name']}. Skipping.")
                continue

            partition_address = self.partitions[write['destination_name']]['address']

            self.logger.info(f"Writing {write['destination_name']}")
            
            self.logger.info(f"Seeking mstarfile to {write['source_address']}")
            self.mstar.seek(write['source_address'])

            self.logger.info(f"Seeking disk to {partition_address}")
            disk.seek(partition_address)

            self.logger.info(f"Writing {write['source_size']}")
            bytes_left = write['source_size']
            while bytes_left > 0:
                chunk_size = bytes_left if bytes_left > 1024 else 1024
                chunk_data = self.mstar.read(chunk_size)
                if len(chunk_data) != chunk_size:
                    raise Exception("Read source failed, read size != chunk size")
                write_size = disk.write(chunk_data)
                if write_size != chunk_size:
                    raise Exception("Write destination failed, write size != chunk size")
                bytes_left -= chunk_size

            self.logger.info(f"Writing {write['destination_name']} complete")
        self.logger.info("Closing disk")
        disk.close()

    def validate(self):
        # open MstarUpgrade
        self.logger.info(f"Opening mstar file: {self.args.mstar}")
        self.mstar = open(self.args.mstar, "rb")

        self.parseUpgradeScript()
        self.dumpUpgradeScriptData()

        self.logger.info("Closing mstar file")
        self.mstar.close()
        

    def write(self):
        # open MstarUpgrade
        self.logger.info(f"Opening mstar file: {self.args.mstar}")
        self.mstar = open(self.args.mstar, "rb")
        
        self.partitions["MBOOT"] = {
            "name": "MBOOT",
            "address": 0x200000
        }
        
        self.parseUpgradeScript()
        self.dumpUpgradeScriptData()

        self.writeBoot()
        self.writePartitions()

        self.logger.info("Closing mstar file")
        self.mstar.close()


if __name__ == '__main__':
    Main()()
