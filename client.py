#!/usr/bin/env python3

import time
import zmq
import msgpack
import subprocess

PUB_TOPIC_DELTA = b"dynfw/delta"
PUB_TOPIC_LIST = b"dynfw/list"

IPSET_NAME = "turris-sn-wan-input-block"

MISSING_UPDATE_CNT_LIMIT = 10

class Ipset:
    commands=[]
    def add_ip(self, ip):
        self.commands.append('add {} {}\n'.format(IPSET_NAME, ip))
    def del_ip(self, ip):
        self.commands.append('del {} {}\n'.format(IPSET_NAME, ip))
    def reset(self):
        self.commands.append('create {} hash:ip -exist\n'.format(IPSET_NAME))
        self.commands.append('flush {}\n'.format(IPSET_NAME))
    def commit(self):
        try:
            p = subprocess.Popen(['/usr/sbin/ipset','restore'], stdin=subprocess.PIPE)
            for cmd in self.commands:
                p.stdin.write(cmd.encode())
            p.stdin.close()
            p.wait()
            self.commands=[]
            if p.returncode==0:
                return True
            else:
                return False
        except OSError:
            return False

def fill_ipset(ips):
    ipset = Ipset()
    ipset.reset()
    for ip in ips:
        ipset.add_ip(ip)
    ipset.commit()

def add_to_ipset(ip):
    ipset = Ipset()
    ipset.add_ip(ip)
    ipset.commit()

def remove_from_ipset(ip):
    ipset = Ipset()
    ipset.del_ip(ip)
    ipset.commit()

def recv_unpack_message(socket):
    msg = socket.recv_multipart()
    msg_decoded = msgpack.unpackb(msg[1], encoding="UTF-8")
    print(msg_decoded)
    return msg_decoded

def reload_list(socket):
    socket.setsockopt(zmq.SUBSCRIBE, PUB_TOPIC_LIST)
    msg_decoded = recv_unpack_message(socket)
    current_serial = msg_decoded["serial"]
    fill_ipset(msg_decoded["list"])
    socket.setsockopt(zmq.UNSUBSCRIBE, PUB_TOPIC_LIST)
    return current_serial

def main():
    if (len(sys.argv)<2):
        print("usage: {} uplink".format(sys.argv[0]))
        sys.exit(1)
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    client_public_file, client_secret_file = zmq.auth.create_certificates("/tmp/", "sentinel_client")
    socket.curve_secretkey = client_secret
    socket.curve_publickey = client_public
    server_public, _ = zmq.auth.load_certificate("/tmp/sentinel_server.key")
    socket.curve_serverkey = server_public
    socket.connect(sys.argv[1]) #tcp://192.168.1.126:5555
    received_out_of_order = set()
    current_serial = reload_list(socket)
    socket.setsockopt(zmq.SUBSCRIBE, PUB_TOPIC_DELTA)
    while True:
        msg_decoded = recv_unpack_message(socket)
        if msg_decoded["delta"] == "positive":
            add_to_ipset(msg_decoded["ip"])
        elif msg_decoded["delta"] == "negative":
            remove_from_ipset(msg_decoded["ip"])
        else:
            print("what the ... ?")
        if msg_decoded["serial"] == current_serial + 1: #received following serial - no missed messages
            current_serial = current_serial + 1
            while current_serial + 1 in received_out_of_order:
                received_out_of_order.remove(current_serial + 1)
                current_serial = current_serial + 1
        else: #missed some messages (or server restarted)
            if msg_decoded["serial"] > current_serial and len(received_out_of_order) < MISSING_UPDATE_CNT_LIMIT:
                received_out_of_order.add(msg_decoded["serial"])
            else:
                socket.setsockopt(zmq.UNSUBSCRIBE, PUB_TOPIC_DELTA)
                current_serial = reload_list(socket)
                socket.setsockopt(zmq.SUBSCRIBE, PUB_TOPIC_DELTA)
                received_out_of_order = set()
        print("current list serial",current_serial)

if __name__ == "__main__":
    main()
