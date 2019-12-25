#!/usr/bin/env python3

import asyncio
from datetime import datetime
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

def log(conn: telnetlib.Telnet, level: str, msg : str):
    now = datetime.now()
    timestamp = now.strftime("%Y.%m.%d %H:%M:%S")
    line = f"[{timestamp}][{level}]: {msg}"
    print(line)
    execute(conn, f"echo {line}")

def get_ip_id(line: str) -> (str, int):
    pattern = r"ClientID=([\d]{1,2}) addr=((?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d))"
    match = re.search(pattern, line)
    if match:
        return match.group(2), match.group(1)
    else:
        return None, None

def decide_is_vpn(conn: telnetlib.Telnet, api_results: dict, ip: str) -> bool:
    get_ip_intel = api_results['GetIPIntel']
    ip_hub = api_results['IPHub']
    ip_theo = api_results['IPTheo']

    true_count = len([value for key, value in api_results.items() if value == True])
    total_count = len(api_results)
    log(conn, "VPN", f"IP: {ip} - GetIPIntel: {int(get_ip_intel)} IPHub: {int(ip_hub)} IPTheo: {int(ip_theo)}")
    return (true_count / total_count) > 0.5


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
    try:
        r = redis.Redis(socket_connect_timeout=1)
        r.ping()
    except:
        print(f"Error: Could not connect to redis cache.")
        r = None

    conn = telnetlib.Telnet()

    while True:
        try:
            # econ connection 
            conn.open(econ_host, econ_port, 60)

            vpn_apis = [("GetIPIntel", API_GetIPIntel_Net(email, 0.95)), ("IPHub", API_IPHub(iphub_token)), ("IPTheo", API_IP_Teoh_IO())]

            if login(conn, password):

                while True:
                    line = read_line(conn)
                    if len(line) > 0:
                        # parses connect message
                        ip, client_id = get_ip_id(line)
                        if ip:
                            # init values
                            exists = None
                            is_vpn_response_dict = {}
                            is_vpn = False
                            got_response = False
                            
                            if r != None:
                                exists = r.get(ip)
                            

                            if exists == None:
                                # does not exist in redis database
                                # needs to be retrieved from api endpoints

                                for key, api in vpn_apis:
                                    err, is_vpn = await api.is_vpn(ip)
                        
                                    if err:
                                        is_vpn_response_dict[key] = None
                                        continue
                                    else:
                                        got_response = True
                                        is_vpn_response_dict[key] = is_vpn

                                
                                if got_response:
                                    # decide based on all three results
                                    is_vpn = decide_is_vpn(conn, is_vpn_response_dict, ip)

                                    # set values in redis database
                                    if r != None:
                                        if is_vpn:
                                            # vpns are being kept forever
                                            r.set(ip, int(is_vpn))
                                            print(f"{ip} is a VPN")
                                        else:
                                            # non vpn ips are being kept for one week, before they are
                                            # checked again.
                                            r.set(ip, int(is_vpn), ex=(3600 * 24 * 7))
                                            print(f"{ip} is not a VPN")
                                else:
                                    # is not vpn, cuz could not retrieve data.
                                    print(f"Could not evaluate {ip} because could not retrieve any VPN data.")
                                    pass
                            else:
                                # exists in db
                                is_vpn = bool(int(exists))
                                log(conn, "VPN", f"IP: {ip} - In cache: {int(is_vpn)}")
                                print(f"{ip} found in cache: {int(is_vpn)}")
                            
                            if is_vpn:
                                execute(conn, f'ban {ip} {vpn_ban_time} "{vpn_ban_reason}"')

            else:
                print("Login failed!")

        except:
            print(f"Error: Could not establish econ connection: {econ_host}:{econ_port}")
            pass
        finally:
            conn.close()
    


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    
    

    
    