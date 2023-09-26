import subprocess
from loguru import logger
import requests
import json
import os
import sys


def download_gadgets():
    frida_version = (
        subprocess.check_output(["frida", "--version"]).decode("utf-8").strip()
    )
    logger.debug(
        "Updating frida gadgets according to your frida version: {0}".format(
            frida_version
        )
    )

    github_link = "https://api.github.com/repos/frida/frida/releases"
    response = requests.get(github_link).text
    releases = json.loads(response)

    release_link = None
    for release in releases:
        if release["tag_name"] == frida_version:
            release_link = release["url"]
            break
    if not release_link:
        raise Exception(
            "Could not find a release for your frida version: {0}".format(frida_version)
        )

    response = requests.get(release_link).text
    release_content = json.loads(response)

    assets = release_content["assets"]
    list_gadgets = []
    for asset in assets:
        if "gadget" in asset["name"] and "android" in asset["name"]:
            gadget = dict()
            gadget["name"] = asset["name"]
            gadget["url"] = asset["browser_download_url"]

            list_gadgets.append(gadget)

    current_folder = os.path.dirname(os.path.abspath(__file__))
    gadgets_folder = os.path.join(current_folder, "gadgets")
    target_folder = os.path.join(gadgets_folder, frida_version)

    if not os.path.isdir(target_folder):
        os.makedirs(target_folder)

    downloaded_files = []
    for gadget in list_gadgets:
        gadget_file_path = os.path.join(target_folder, gadget["name"])

        if os.path.isfile(gadget_file_path.replace(".xz", "")):
            logger.debug("{0} already exists. Skipping.".format(gadget["name"]))
        else:
            __download_file(gadget["url"], gadget_file_path)
            downloaded_files.append(gadget_file_path)

    logger.debug("Extracting downloaded files...")

    for downloaded_file in downloaded_files:
        subprocess.check_output(["unxz", downloaded_file])

    logger.debug("Done! Gadgets were updated")


def __download_file(url: str, target_path: str):
    response = requests.get(url, stream=True)
    total_length = response.headers.get("content-length")
    if not total_length:
        raise Exception(
            "Could not get the total length of the file. Aborting download."
        )
    total_length = int(total_length)

    with open(target_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=1024):
            if not chunk:
                continue
            f.write(chunk)
