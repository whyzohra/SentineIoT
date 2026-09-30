"""CDK app entry point. `python aws_pipeline/app.py` synthesizes without AWS access."""

import aws_cdk as cdk
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aws_pipeline.stack import SentinelOTSecurityStack

app = cdk.App(outdir=os.environ.get("CDK_OUTDIR", str(Path(__file__).resolve().parent / "cdk.out")))
SentinelOTSecurityStack(app, "SentinelOTSecurity")
app.synth()
