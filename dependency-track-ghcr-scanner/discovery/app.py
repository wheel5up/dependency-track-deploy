import json
import os

import boto3
import neo4j

# Cartography's own Bolt endpoint and NEO4J_AUTH=none reality -- see
# README.md "Where the Neo4j connection details come from" for why these
# are SSM-resolved template parameters (not hardcoded here) and why no
# NEO4J_USER/NEO4J_PASSWORD env vars exist (Neo4j auth is assumed off,
# with access limited by security group).
NEO4J_URI = os.environ["NEO4J_URI"]
NEO4J_DATABASE = os.environ.get("NEO4J_DATABASE") or None
NEO4J_MAX_CONNECTION_LIFETIME = int(os.environ.get("NEO4J_MAX_CONNECTION_LIFETIME", "200"))

IMAGE_LIST_SSM_PARAMETER_NAME = os.environ["IMAGE_LIST_SSM_PARAMETER_NAME"]

ssm_client = boto3.client("ssm")

# All distinct ghcr.io image references currently running anywhere on
# the Kubernetes fleet, regardless of which org/owner published them --
# deliberately NOT filtered to your own orgs only. See
# README.md "Why unfiltered -- scanning third-party images too" for the
# reasoning (you don't control the fix for a third-party image, but you
# still want to know if it's a live CVE in your own cluster).
#
# KubernetesContainer.image is the actual running reference (a tag,
# not necessarily a resolved digest -- see README.md "Tag vs digest
# identity" for why this is fine here even though ECR's own pipeline
# uses a resolved digest instead).
DISCOVERY_QUERY = """
MATCH (c:KubernetesContainer)
WHERE c.image CONTAINS 'ghcr.io'
RETURN DISTINCT c.image AS image
ORDER BY image
"""


def _get_neo4j_driver():
    return neo4j.GraphDatabase.driver(
        NEO4J_URI,
        auth=None,
        max_connection_lifetime=NEO4J_MAX_CONNECTION_LIFETIME,
    )


def lambda_handler(event, context):
    driver = _get_neo4j_driver()
    try:
        with driver.session(database=NEO4J_DATABASE) as session:
            result = session.run(DISCOVERY_QUERY)
            images = [record["image"] for record in result]
    finally:
        driver.close()

    # SSM Advanced tier (8 KB) required -- the full unfiltered list
    # measured ~6 KB at 99 images, over Standard tier's 4 KB cap. See
    # README.md "Why SSM Advanced, not S3 or Standard tier".
    ssm_client.put_parameter(
        Name=IMAGE_LIST_SSM_PARAMETER_NAME,
        Value=json.dumps(images),
        Type="String",
        Tier="Advanced",
        Overwrite=True,
    )

    return {
        "status": "SUCCEEDED",
        "imageCount": len(images),
        "ssmParameterName": IMAGE_LIST_SSM_PARAMETER_NAME,
    }
