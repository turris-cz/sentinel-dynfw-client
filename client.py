#!/usr/bin/env python3

import subprocess
import sys
import os
import logging
import argparse
import zmq
import zmq.auth
import msgpack

logger = logging.getLogger('sentinel_dynfw_client')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

CLIENT_CERT_PATH = "/tmp/sentinel/"

PUB_TOPIC_DELTA = b"dynfw/delta"
PUB_TOPIC_LIST = b"dynfw/list"

IPSET_NAME = "turris-sn-wan-input-block"

FIRST_MESSAGE_TIMEOUT = 60*1000
MISSING_UPDATE_CNT_LIMIT = 10

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
    parser.add_argument('-p', '--port', type=int, default=5555, help='Server port')
    parser.add_argument('-c', '--cert', default="/tmp/sentinel_server.key", help='Server certificate (ZMQ)')
    args = parser.parse_args()
    received_out_of_order = set()
    context = zmq.Context()
    socket = create_zmq_socket(context, args.cert)
    socket.connect("tcp://{}:{}".format(args.server, args.port)) #tcp://192.168.1.126:5555
    socket.setsockopt(zmq.RCVTIMEO, FIRST_MESSAGE_TIMEOUT)
    try:
        current_serial = reload_list(socket)
    except zmq.error.Again:
        logger.error("No LIST message received from server within %d seconds. This probably means we can't connect.", int(FIRST_MESSAGE_TIMEOUT/1000))
        #... and what's worse, ZMQ won't tell us if the error is permanent (e.g. invalid certificate) or just temporary (no connectivity)
        #so we exit -> init will restart the service and we hope that the problem will solve itself eventually
        sys.exit(1)
    socket.setsockopt(zmq.RCVTIMEO, -1)
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
                logger.warn("received unknown DELTA message: %s", str(msg_decoded))
            ipset.commit()
            if msg_decoded["serial"] == current_serial + 1: #received following serial - no missed messages
                current_serial = current_serial + 1
                while current_serial + 1 in received_out_of_order:
                    received_out_of_order.remove(current_serial + 1)
                    current_serial = current_serial + 1
            else: #missed some messages (or server restarted)
                if msg_decoded["serial"] > current_serial and len(received_out_of_order) < MISSING_UPDATE_CNT_LIMIT:
                    received_out_of_order.add(msg_decoded["serial"])
                    logger.debug("received out-of-order message: received serial %d, missing serial %d.", msg_decoded["serial"], current_serial + 1)
                else: #missed too many messages, reloading the whole list
                    logger.info("too many messages are out-of-order, reloading the whole list")
                    socket.setsockopt(zmq.UNSUBSCRIBE, PUB_TOPIC_DELTA)
                    current_serial = reload_list(socket)
                    socket.setsockopt(zmq.SUBSCRIBE, PUB_TOPIC_DELTA)
                    received_out_of_order = set()
        except KeyError as e:
            logger.warn("missing mandatory key in DELTA message: %s", str(e))

if __name__ == "__main__":
    main()
