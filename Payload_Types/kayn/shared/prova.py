import mythic
from mythic import mythic_rest
import asyncio

async def initialize():
    mythic_instance = mythic_rest.Mythic(
        username="admin",
        password="admin",
        server_ip="192.168.1.11",
        server_port="7443",
        ssl=True,
        global_timeout=-1,
    )

    print("[+] Logging into Mythic")
    await mythic_instance.login()
    await mythic_instance.set_or_create_apitoken()
    print("[+] Listening for new responses")

    resp = await mythic_instance.get_all_callbacks()

    for c in resp.response:
        if c.active:
            print(c.ip)

loop = asyncio.get_event_loop()
loop.create_task(initialize())
