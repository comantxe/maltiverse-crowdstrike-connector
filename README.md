# maltiverse-crowdstrike-connector
A connector to upload Maltiverse Threat Intelligence to Crowdstrike

options:

  -h, --help                                                show this help message and exit
  
  --maltiverse_api_key MALTIVERSE_API_KEY                   Specifies Maltiverse API KEY. Required
  
  --crowdstrike_client_id CROWDSTRIKE_CLIENT_ID             Specify the Crowdstrike CLIENT_ID. Required
  
  --crowdstrike_client_secret CROWDSTRIKE_CLIENT_SECRET     Specifies Crowdstrike CLIENT_SECRET. Required
  
  --feed_id FEED_ID                                         Specifies Maltiverse Feed ID to upload to CrowdStrike Falcon cloud. Required
  
  --action ACTION                                           Specifies the action that applies to the uploading indicators. Default: detect
