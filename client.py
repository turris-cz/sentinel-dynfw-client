#!/usr/bin/env python3

# Turris:Sentinel DynFW client - client application for sentinel dynamic firewall
# Copyright (C) 2018 CZ.NIC z.s.p.o. (https://www.nic.cz/)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import subprocess
import sys
import os
import logging
import argparse
import zmq
import zmq.auth
from zmq.utils.monitor import recv_monitor_message
import msgpack

logger = logging.getLogger("sentinel_dynfw_client")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

CLIENT_CERT_PATH = "/tmp/sentinel/"

TOPIC_DYNFW_DELTA = "dynfw/delta"
TOPIC_DYNFW_LIST = "dynfw/list"

DYNFW_IPSET_NAME = "turris-sn-wan-input-block"

MISSING_UPDATE_CNT_LIMIT = 10


def wait_for_connection(socket):
    monitor = socket.get_monitor_socket()
    logger.debug("waiting for connection")
    while monitor.poll():
        evt = recv_monitor_message(monitor)
        if evt['event'] == zmq.EVENT_CONNECTED:
            logger.debug("connected")
            break
        if evt['event'] == 0x0800 or evt['event'] == 0x2000 or evt['event'] == 0x4000:
            # detect handshake failure
            # unfortunatelly, these constants are not yet in pyzmq
            # constants from https://github.com/zeromq/libzmq/blob/c8a1c4542d13b6492949e7525f4fe8da266cac2b/src/zmq_draft.h#L60
            # 0x0800 - ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL
            # 0x2000 - ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL
            # 0x4000 - ZMQ_EVENT_HANDSHAKE_FAILED_AUTH
            logger.error("Can't connect - handshake failed.")
            print("Can't connect - handshake failed.", file=sys.stderr)
            sys.exit(1)
    monitor.close()
    socket.disable_monitor()


class Ipset:
    def __init__(self, name):
        self.name = name
        self.commands = []

    def add_ip(self, ip):
        self.commands.append('add {} {}\n'.format(self.name, ip))

    def del_ip(self, ip):
        self.commands.append('del {} {}\n'.format(self.name, ip))

    def reset(self):
        self.commands.append('create {} hash:ip -exist\n'.format(self.name))
        self.commands.append('flush {}\n'.format(self.name))

    def commit(self):
        try:
            p = subprocess.Popen(['/usr/sbin/ipset', 'restore'], stdin=subprocess.PIPE)
            for cmd in self.commands:
                p.stdin.write(cmd.encode('utf-8'))
            p.stdin.close()
            p.wait()
            self.commands = []
            if p.returncode != 0:
                logger.warn("Error running ipset command: return code %d.", p.returncode)
        except (PermissionError, FileNotFoundError) as e:
            # these errors are permanent, i.e., they won't disappear upon next run
            logger.critical("Can't run ipset command: %s.", str(e))
            print("Can't run ipset command: {}.".format(str(e)), file=sys.stderr)
            sys.exit(1)
        except OSError as e:
            # the rest of OSError should be temporary, e.g., ChildProcessError or BrokenPipeError
            logger.warn("Error running ipset command: %s.", str(e))


def create_zmq_socket(context, server_public_file):
    socket = context.socket(zmq.SUB)
    if not os.path.exists(CLIENT_CERT_PATH):
        os.mkdir(CLIENT_CERT_PATH)
    _, client_secret_file = zmq.auth.create_certificates(CLIENT_CERT_PATH, "client")
    client_public, client_secret = zmq.auth.load_certificate(client_secret_file)
    socket.curve_secretkey = client_secret
    socket.curve_publickey = client_public
    server_public, _ = zmq.auth.load_certificate(server_public_file)
    socket.curve_serverkey = server_public
    return socket


class InvalidMsgError(Exception):
    pass


def parse_msg(data):
    try:
        msg_type = str(data[0], encoding="UTF-8")
        payload = msgpack.unpackb(data[1], encoding="UTF-8")
    except IndexError:
        raise InvalidMsgError("Not enough parts in message")
    except (TypeError, msgpack.exceptions.UnpackException, UnicodeDecodeError):
        raise InvalidMsgError("Broken message")
    return msg_type, payload


class Serial():
    def __init__(self, missing_limit):
        self.missing_limit = missing_limit
        self.received_out_of_order = set()
        self.current_serial = 0

    def update_ok(self, serial):
        # update serial & return bool
        # return whether the serial is ok or if the list should be reloaded
        if serial == self.current_serial + 1:
            # received expected serial
            self.current_serial = serial
            while self.current_serial + 1 in self.received_out_of_order:
                # rewind serials
                self.current_serial = self.current_serial + 1
                self.received_out_of_order.remove(self.current_serial)
            return True
        else:
            if serial < self.current_serial:
                logger.debug("received lower serial (restarted server?)")
                return False
            if len(self.received_out_of_order) > self.missing_limit:
                logger.debug("too many missed messages")
                return False
            self.received_out_of_order.add(serial)
            return True

    def reset(self, serial):
        # reset serial - after list reload
        self.received_out_of_order = set()
        self.current_serial = serial


class DynfwList():
    def __init__(self, socket):
        self.socket = socket
        self.serial = Serial(MISSING_UPDATE_CNT_LIMIT)
        self.ipset = Ipset(DYNFW_IPSET_NAME)
        self.socket.setsockopt(zmq.SUBSCRIBE, TOPIC_DYNFW_LIST.encode('utf-8'))

    def handle_delta(self, msg):
        if "serial" not in msg or "delta" not in msg or "ip" not in msg:
            raise InvalidMsgError("missing map key")
        if not self.serial.update_ok(msg["serial"]):
            logger.debug("going to reload the whole list")
            self.socket.setsockopt(zmq.UNSUBSCRIBE, TOPIC_DYNFW_DELTA.encode('utf-8'))
            self.socket.setsockopt(zmq.SUBSCRIBE, TOPIC_DYNFW_LIST.encode('utf-8'))
            return
        if msg["delta"] == "positive":
            self.ipset.add_ip(msg["ip"])
            logger.debug("DELTA message: +%s, serial %d", msg["ip"], msg["serial"])
        elif msg["delta"] == "negative":
            self.ipset.del_ip(msg["ip"])
            logger.debug("DELTA message: -%s, serial %d", msg["ip"], msg["serial"])
        self.ipset.commit()

    def handle_list(self, msg):
        if "serial" not in msg or "list" not in msg:
            raise InvalidMsgError("missing map key")
        self.serial.reset(msg["serial"])
        self.ipset.reset()
        for ip in msg["list"]:
            self.ipset.add_ip(ip)
        self.ipset.commit()
        logger.debug("LIST message - %s addresses, serial %d", len(msg["list"]), msg["serial"])
        self.socket.setsockopt(zmq.UNSUBSCRIBE, TOPIC_DYNFW_LIST.encode('utf-8'))
        self.socket.setsockopt(zmq.SUBSCRIBE, TOPIC_DYNFW_DELTA.encode('utf-8'))


def parse_args():
    parser = argparse.ArgumentParser(description='Turris::Sentinel Dynamic Firewall Client')
    parser.add_argument('-s',
                        '--server',
                        default="sentinel.turris.cz",
                        help='Server address'
                       )
    parser.add_argument('-p',
                        '--port',
                        type=int,
                        default=7087,
                        help='Server port'
                       )
    parser.add_argument('-c',
                        '--cert',
                        default="/tmp/sentinel_server.key",
                        help='Server ZMQ certificate'
                       )
    return parser.parse_args()


def main():
    args = parse_args()
    context = zmq.Context()
    socket = create_zmq_socket(context, args.cert)
    socket.connect("tcp://{}:{}".format(args.server, args.port))
    wait_for_connection(socket)
    dynfw_list = DynfwList(socket)
    while True:
        msg = socket.recv_multipart()
        try:
            topic, payload = parse_msg(msg)
            if topic == TOPIC_DYNFW_LIST:
                dynfw_list.handle_list(payload)
            elif topic == TOPIC_DYNFW_DELTA:
                dynfw_list.handle_delta(payload)
            else:
                logger.warning("received unknown topic: %s", topic)
        except InvalidMsgError as e:
            logger.error("Invalid message: %s", e)


if __name__ == "__main__":
    main()
