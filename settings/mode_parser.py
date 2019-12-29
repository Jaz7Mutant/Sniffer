import argparse
import glob
import os
import socket
import sys
from typing import List

from network_analyzer.tracking_connection import TrackingConnection
from unpacker.linux_socket import LinuxSocket
from unpacker.socket_handler import SocketHandler
from unpacker.windows_socket import WindowsSocket


class ModeParser:
    def get_settings(self) -> (bool, bool, bool, bool):
        namespace = self._get_args()
        return (
            namespace.console,
            namespace.plot,
            namespace.dump,
            namespace.send
        )

    def get_socket(self) -> SocketHandler:
        if sys.platform == 'win32':
            interface = self._get_windows_interface()
            return WindowsSocket(interface)
        elif sys.platform == 'linux2' or sys.platform == 'linux':
            interface = self._get_linux_interface()
            return LinuxSocket(interface)
        else:
            print(sys.platform)
            raise NotImplementedError('Your OS is not supported')

    @staticmethod
    def get_dump_name() -> str:
        print('Choose the dump file:')
        files = os.listdir('dump')
        for file in files:
            if file[0] == '#':
                print(file)
        filename = input('Write file number (#xxx)\n')
        a = glob.glob(f'dump/{filename}*')[0]
        print(a)
        return a

    @staticmethod
    def get_tracking_connections(write_to_pcap) -> List[TrackingConnection]:
        tracking_conns = list()
        while True:
            print('Write source_ip and target_ip (X.X.X.X X.X.X.X) '
                  'or "ALL" to catch all packets')
            print('Write empty string to finish')
            raw_string = input()
            if raw_string == '':
                break
            if raw_string == 'ALL':
                tracking_conns.append(
                    TrackingConnection('ALL', 'ALL', write_to_pcap, True)
                )
                continue
            source, target = raw_string.split(' ')
            tracking_conns.append(
                TrackingConnection(source, target, write_to_pcap, True)
            )
        return tracking_conns

    @staticmethod
    def _get_windows_interface():
        from scapy.arch import IFACES
        IFACES.show()
        interface_index = input('Choose the interface by index... \n')
        return IFACES.dev_from_index(interface_index)

    @staticmethod
    def _get_linux_interface() -> str:
        print('№  Interface')
        for line in socket.if_nameindex():
            print(f'{line[0]}. {line[1]}')
        interface_index = int(input('Choose the interface by index... \n'))
        return socket.if_nameindex()[interface_index - 1][1]

    @staticmethod
    def _get_args() -> argparse.Namespace:
        parser = argparse.ArgumentParser(add_help=True)

        parser.add_argument(
            '-c',
            '--console',
            help='Show parsed info in console',
            action='store_true'
        )

        parser.add_argument(
            '-p',
            '--plot',
            help='Show plot of network load',
            action='store_true'
        )

        parser.add_argument(
            '-d',
            '--dump',
            help='Write dumps for every tracking connection',
            action='store_true'
        )

        parser.add_argument(
            '-s',
            '--send',
            help='Send frames from pcap dump',
            action='store_true'
        )
        return parser.parse_args()
