#!/usr/bin/env python3

import subprocess
import sys
import os
import logging
import threading
import argparse
import zmq
import zmq.auth
from zmq.utils.monitor import recv_monitor_message
import msgpack

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("sentinel_dynfw_client")

CLIENT_CERT_PATH = "/tmp/sentinel/"

PUB_TOPIC_DELTA = b"dynfw/delta"
PUB_TOPIC_LIST = b"dynfw/list"

IPSET_NAME = "turris-sn-wan-input-block"

MISSING_UPDATE_CNT_LIMIT = 10


def event_monitor(monitor):
    while monitor.poll():
        evt = recv_monitor_message(monitor)
        # unfortunatelly, these constants are not yet in pyzmq (these event are still in DRAFT more in libzmq)
        # constants from https://github.com/zeromq/libzmq/blob/c8a1c4542d13b6492949e7525f4fe8da266cac2b/src/zmq_draft.h#L60
        if evt['event'] == 0x0800 or evt['event'] == 0x2000 or evt['event'] == 0x4000:
            logger.error("Can't connect - handshake failed")
            os._exit(1)
        if evt['event'] == zmq.EVENT_MONITOR_STOPPED:
            break
    monitor.close()


class Ipset:
    def __init__(self):
        self.commands = []

    def add_ip(self, ip):
        self.commands.append('add {} {}\n'.format(IPSET_NAME, ip))

    def del_ip(self, ip):
        self.commands.append('del {} {}\n'.format(IPSET_NAME, ip))

    def reset(self):
        self.commands.append('create {} hash:ip -exist\n'.format(IPSET_NAME))
        self.commands.append('flush {}\n'.format(IPSET_NAME))

    def commit(self):
        try:
            p = subprocess.Popen(['/usr/sbin/ipset', 'restore'], stdin=subprocess.PIPE)
            for cmd in self.commands:
                p.stdin.write(cmd.encode())
            p.stdin.close()
            p.wait()
            self.commands = []
            return p.returncode == 0
        except OSError as e:
            logger.critical("can't run ipset command: %s. Can't continue, exiting now.", str(e))
            sys.exit(1)


def recv_unpack_message(socket):
    msg = socket.recv_multipart()
    msg_decoded = msgpack.unpackb(msg[1], encoding="UTF-8")
    return msg_decoded


def reload_list(socket):
    socket.setsockopt(zmq.SUBSCRIBE, PUB_TOPIC_LIST)
    msg_decoded = recv_unpack_message(socket)
    try:
        current_serial = msg_decoded["serial"]
        ipset = Ipset()
        ipset.reset()
        for ip in msg_decoded["list"]:
            ipset.add_ip(ip)
        ipset.commit()
    except KeyError as e:
        logger.critical("missing mandatory key in LIST message: %s. Can't continue, exiting now.", str(e))
        sys.exit(1)
    socket.setsockopt(zmq.UNSUBSCRIBE, PUB_TOPIC_LIST)
    logger.debug("reloaded list - %s addresses, serial %d", len(msg_decoded["list"]), current_serial)
    return current_serial


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


def main():
    parser = argparse.ArgumentParser(description='Turris::Sentinel Dynamic Firewall Client')
    parser.add_argument('-s', '--server', default="sentinel.turris.cz", help='Server address')
    parser.add_argument('-p', '--port', type=int, default=7087, help='Server port')
    parser.add_argument('-c', '--cert', default="/tmp/sentinel_server.key", help='Server certificate (ZMQ)')
    args = parser.parse_args()
    context = zmq.Context()
    socket = create_zmq_socket(context, args.cert)
    socket.connect("tcp://{}:{}".format(args.server, args.port))
    monitor = socket.get_monitor_socket()
    # we use monitor just to notice initial authentification failure
    t = threading.Thread(target=event_monitor, args=(monitor,), daemon=True)
    t.start()
    try:
        current_serial = reload_list(socket)
    finally:  # in case of interrupt, terminate the monitor thread
        socket.disable_monitor()
    received_out_of_order = set()
    socket.setsockopt(zmq.SUBSCRIBE, PUB_TOPIC_DELTA)
    while True:
        try:
            msg_decoded = recv_unpack_message(socket)
            ipset = Ipset()
            if msg_decoded["delta"] == "positive":
                ipset.add_ip(msg_decoded["ip"])
                logger.debug("received DELTA message: + %s, serial %d", msg_decoded["ip"], msg_decoded["serial"])
            elif msg_decoded["delta"] == "negative":
                ipset.del_ip(msg_decoded["ip"])
                logger.debug("received DELTA message: - %s, serial %d", msg_decoded["ip"], msg_decoded["serial"])
            else:
                logger.warning("received unknown DELTA message: %s", str(msg_decoded))
                continue
            ipset.commit()
            if msg_decoded["serial"] == current_serial + 1:  # received expected serial - no missed messages
                current_serial = current_serial + 1
                while current_serial + 1 in received_out_of_order:
                    received_out_of_order.remove(current_serial + 1)
                    current_serial = current_serial + 1
            else:  # missed some messages (or server restarted)
                if msg_decoded["serial"] > current_serial and len(received_out_of_order) < MISSING_UPDATE_CNT_LIMIT:
                    received_out_of_order.add(msg_decoded["serial"])
                    logger.debug("message out-of-order: received serial %d, missing serial %d.", msg_decoded["serial"], current_serial + 1)
                else:  # missed too many messages, reloading the whole list
                    logger.info("too many messages are out-of-order, reloading the whole list")
                    socket.setsockopt(zmq.UNSUBSCRIBE, PUB_TOPIC_DELTA)
                    current_serial = reload_list(socket)
                    socket.setsockopt(zmq.SUBSCRIBE, PUB_TOPIC_DELTA)
                    received_out_of_order = set()
        except KeyError as e:
            logger.warning("missing mandatory key in DELTA message: %s", str(e))


if __name__ == "__main__":
    main()
