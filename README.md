# Turris Sentinel Dynamic Firewall client

This client receives Sentinel Dynamic Firewall (Sentinel:DynFW) updates over
ZMQ and updates ipset accordingly.


## Requirements

See `requirements.txt` for needed Python3 packages.


## DynFW certificate

You can download Sentinel:DynFW ZMQ certificate via:

```sh
curl -LO https://repo.turris.cz/sentinel/dynfw.pub
```

and then run the client:
```sh
python client.py --cert dynfw.pub
```
