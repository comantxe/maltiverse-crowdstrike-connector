# maltiverse-crowdstrike-connector
A connector to upload Maltiverse Threat Intelligence to Crowdstrike
```
usage: maltiverse-crowdstrike-connector.py [-h] --maltiverse_api_key MALTIVERSE_API_KEY --crowdstrike_client_id CROWDSTRIKE_CLIENT_ID --crowdstrike_client_secret
                                           CROWDSTRIKE_CLIENT_SECRET [--crowdstrike_base_url CROWDSTRIKE_BASE_URL] --feed_id FEED_ID [--action ACTION]

options:
  -h, --help            show this help message and exit
  --maltiverse_api_key MALTIVERSE_API_KEY
                        Specifies Maltiverse API KEY. Required
  --crowdstrike_client_id CROWDSTRIKE_CLIENT_ID
                        Specify the Crowdstrike CLIENT_ID.
  --crowdstrike_client_secret CROWDSTRIKE_CLIENT_SECRET
                        Specifies Crowdstrike CLIENT_SECRET.
  --crowdstrike_base_url CROWDSTRIKE_BASE_URL
                        Specifies Crowdstrike Base URL.
  --feed_id FEED_ID     Specifies Maltiverse Feed ID to upload to CrowdStrike Falcon cloud. Required
  --action ACTION       Specifies the action that applies to the uploading indicators. Default: detect
```
