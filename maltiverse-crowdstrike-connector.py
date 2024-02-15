#!/usr/bin/python3

# -----------------------------------------------------------
# Python client that retrieves a feed from Maltiverse.com
# Stores results in CrowdStrike Falcon cloud instance
#
# (C) 2024 Maltiverse
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

import argparse
import requests
import json
from datetime import datetime, timedelta
from falconpy import APIHarnessV2


class MaltiverseCrowdStrikeHandler:
    def __init__(self, api_key, client_id, client_secret):
        self.api_key = api_key
        self.base_url = "https://api.maltiverse.com"
        self.headers = {"Authorization": f"Bearer {self.api_key}"}

        self.falcon = APIHarnessV2(
            client_id=client_id,
            client_secret=client_secret,
        )

    def get_feed_metadata_from_maltiverse(self, feed_id):
        """
        Gets a feed metadata from Maltiverse given its Id.
        """
        url = f"{self.base_url}/collection/{feed_id}"
        response = requests.get(url, headers=self.headers)
        return response.json()

    def download_feed_from_maltiverse(self, feed_id):
        """
        Downloads a feed from Maltiverse given its Id.
        """
        url = f"{self.base_url}/collection/{feed_id}/download"
        response = requests.get(url, headers=self.headers)
        return response.json()

    def convert_maltiverse_feed_to_crowdstrike(self, feed_id):
        """
        Converts a maltiverse feed in its original format to a Crowdstrike format
        """
        metadata_maltiverse_feed = self.get_feed_metadata_from_maltiverse(feed_id)
        raw_maltiverse_feed = self.download_feed_from_maltiverse(feed_id)

        cs_indicators = []
        for element in raw_maltiverse_feed:
            objs = handler.convert_obj_maltiverse_to_crowdstrike(element)
            for obj in objs:
                cs_indicators.append(obj)

        response = {
            "comment": f"Maltiverse {metadata_maltiverse_feed['name']} Feed - {metadata_maltiverse_feed['modification_time']}",
            "indicators": cs_indicators,
        }
        return response

    def upload_maltiverse_feed_to_crowdstrike(self, feed_id):
        """
        Given its FEED_ID Uploads a Maltiverse feed to Crowdstrike
        """
        return self.falcon.command(
            "indicator_create_v1",
            retrodetects=False,
            ignore_warnings=False,
            body=self.convert_maltiverse_feed_to_crowdstrike(feed_id),
        )

    def convert_obj_maltiverse_to_crowdstrike(
        self, maltiverse_ioc, action="detect", expiration_days=1
    ):
        """
        Given a Maltiverse IoC returns a CrowdStrike IoC
        """
        ret = []
        expiration_time = None
        if expiration_days:
            expiration_datetime = datetime.now() + timedelta(days=expiration_days)
            expiration_time = expiration_datetime.isoformat() + "Z"

        crowdstrike_ioc_type = None
        crowdstrike_ioc_value = None
        if maltiverse_ioc["type"] == "ip":
            crowdstrike_ioc_type = "ipv4"
            crowdstrike_ioc_value = maltiverse_ioc["ip_addr"]
        if maltiverse_ioc["type"] == "hostname":
            crowdstrike_ioc_type = "domain"
            crowdstrike_ioc_value = maltiverse_ioc["hostname"]
        if maltiverse_ioc["type"] == "url":
            crowdstrike_ioc_type = "url"
            crowdstrike_ioc_value = maltiverse_ioc["url"]
        if maltiverse_ioc["type"] == "sample":
            crowdstrike_ioc_type = "sha256"
            crowdstrike_ioc_value = maltiverse_ioc["sha256"]

        crowdstrike_ioc_severity = "LOW"
        if maltiverse_ioc["classification"] == "malicious":
            crowdstrike_ioc_severity = "HIGH"
        if maltiverse_ioc["classification"] == "suspicious":
            crowdstrike_ioc_severity = "MEDIUM"

        for bl in maltiverse_ioc["blacklist"]:
            crowdstrike_ioc = {
                "action": action,
                "applied_globally": True,
                "expiration": expiration_time,
                "severity": crowdstrike_ioc_severity,
                "source": bl["source"],
                "platforms": ["Mac", "Windows", "Linux"],
                "description": bl["description"],
                "type": crowdstrike_ioc_type,
                "value": crowdstrike_ioc_value,
            }

            if "tag" in maltiverse_ioc:
                crowdstrike_ioc["tags"] = maltiverse_ioc["tag"]

            if "filename" in maltiverse_ioc:
                crowdstrike_ioc["metadata"] = {
                    "filename": maltiverse_ioc["filename"][0]
                }
            ret.append(crowdstrike_ioc)
        return ret


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--maltiverse_api_key",
        dest="maltiverse_api_key",
        required=True,
        help="Specifies Maltiverse API KEY. Required",
    )
    parser.add_argument(
        "--feed_id",
        dest="feed_id",
        required=True,
        help="Specifies Maltiverse Feed ID to retrieve. Required",
    )
    parser.add_argument(
        "--crowdstrike_client_id",
        dest="crowdstrike_client_id",
        required=True,
        help="Specify the Crowdstrike CLIENT_ID.",
    )
    parser.add_argument(
        "--crowdstrike_client_secret",
        dest="crowdstrike_client_secret",
        required=True,
        help="Specifies Crowdstrike CLIENT_SECRET.",
    )

    arguments = parser.parse_args()

    handler = MaltiverseCrowdStrikeHandler(
        arguments.maltiverse_api_key,
        arguments.crowdstrike_client_id,
        arguments.crowdstrike_client_secret,
    )

    res = handler.upload_maltiverse_feed_to_crowdstrike(arguments.feed_id)
    print(json.dumps(res, indent=4))
