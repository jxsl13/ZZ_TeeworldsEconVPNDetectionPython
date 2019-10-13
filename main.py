#!/usr/bin/env python3

import asyncio
import os
import re
import telnetlib

from dotenv import load_dotenv
import redis

from vpn_apis import API_GetIPIntel_Net, API_IP_Teoh_IO, API_IPHub


def execute(conn: telnetlib.Telnet, line: str) -> None:
    """
    executes an econ command.
    """
    cmd = f"{line}\n".encode('utf-8')
    conn.write(cmd)

def read_line(conn: telnetlib.Telnet, timeout=None) -> str:
    """
    wait until a line can be read or if the timeout is reached
    """
    line = conn.read_until(b"\n", timeout=timeout)
    return line.decode('utf-8')[:-1]

def login(conn: telnetlib.Telnet, password: str) -> bool:
    conn.read_until(b"Enter password:\n")
    execute(conn, password)
    res = read_line(conn)
    if res == "Authentication successful. External console access granted.":
        return True
    else:
        return False

def get_ip_id(line: str) -> (str, int):
    pattern = r"ClientID=([\d]{1,2}) addr=((?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d))"
    match = re.search(pattern, line)
    if match:
        return match.group(2), match.group(1)
    else:
        return None, None


async def main():
    load_dotenv()

    email = os.getenv('EMAIL')
    iphub_token = os.getenv('IPHUB_TOKEN')

    econ_host = os.getenv("ECON_HOST")
    econ_port = int(os.getenv("ECON_PORT"))
    password = os.getenv("ECON_PASSWORD")

    vpn_ban_time = int(os.getenv("VPN_BAN_TIME"))
    vpn_ban_reason = os.getenv("VPN_BAN_REASON")

    # database
    r = redis.Redis()

    # econ connection
    conn = telnetlib.Telnet()
    conn.open(econ_host, econ_port)

    vpn_apis = [API_GetIPIntel_Net(email, 1), API_IPHub(iphub_token), API_IP_Teoh_IO()]

    if login(conn, password):

        while True:
            line = read_line(conn)
            if len(line) > 0:
                # parses connect message
                ip, client_id = get_ip_id(line)
                if ip:
                    # init values
                    is_vpn = False
                    got_response = False

                    exists = r.get(ip)

                    if exists == None:
                        # does not exist in redis database
                        # needs to be retrieved from api endpoints

                        for api in vpn_apis:
                            err, is_vpn = await api.is_vpn(ip)
                
                            if err:
                                continue
                            else:
                                got_response = True
                                if is_vpn:
                                    break
                        
                        if got_response:
                            if is_vpn:
                                # vpns are being kept forever
                                r.set(ip, int(is_vpn))
                            else:
                                # non vpn ips are being kept for one week, before they are
                                # checked again.
                                r.set(ip, int(is_vpn), ex=(3600 * 24 * 7))
                        else:
                            # is not vpn, cuz could not retrieve data.
                            pass
                    else:
                        # exists in db
                        is_vpn = bool(int(exists))
                    
                    if is_vpn:
                        execute(conn, f'ban {client_id} {vpn_ban_time} "{vpn_ban_reason}"')

    else:
        print("Login failed!")
    conn.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    
    

    
    