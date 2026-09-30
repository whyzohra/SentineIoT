# Local demo walkthrough

This walkthrough uses synthetic records, a local SQLite file, and a loopback dashboard. No cloud account, FortiGate device, or OT equipment is used.

## 1. Prepare the environment

From the repository root in PowerShell:

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
cd dashboard
npm ci
cd ..
```

For macOS/Linux, activate with `source .venv/bin/activate`. `requirements-dev.txt` includes test, ML, and CDK dependencies; AWS credentials are not needed for the local demo.

## 2. Run a complete incident demo

In the first terminal, generate a deterministic network reconnaissance scenario and persist its alert, risk assessment, and incident:

```powershell
python -m incident_management demo network_recon --seed 7 --db .sentinelot-demo.sqlite3
python -m incident_management list --db .sentinelot-demo.sqlite3
```

The simulation is event generation only. The output includes supporting synthetic event IDs, rule alert, ATT&CK enrichment when applicable, risk factors, and incident details.

## 3. Inspect it in the dashboard

Start the API from the repository root in another terminal:

```powershell
python -m dashboard_api --db .sentinelot-demo.sqlite3 --port 8000
```

Start the UI in a third terminal:

```powershell
cd dashboard
npm run dev
```

Open the loopback URL printed by Vite. Use the incident investigation view to review the alert evidence, risk rationale, MITRE data, timeline, and audit trail. Response playbooks are derived from incident evidence. Requesting a playbook does not run it: separately check the authorization control and provide an authorization reason to record a simulated outcome. Every result is explicitly a simulation.

## Other deterministic demos

Run an isolated simulation or each optional component from the repository root:

```powershell
python -m attack_simulator run unauthorized_plc --seed 7
python -m detection_engine demo brute_force --seed 7 --count 12
python -m risk_engine demo network_recon --seed 7
python -m fortigate demo --db .sentinelot-demo.sqlite3
python -m ml_detection demo --seed 7 --db .sentinelot-ml-demo.sqlite3
python -m aws_pipeline demo network_recon --seed 7
```

The FortiGate command uses bundled synthetic JSONL fixtures. The ML command trains on its synthetic baseline. The AWS command exercises pipeline stages locally and does not contact AWS. CDK infrastructure synthesis is separate:

```powershell
python aws_pipeline/app.py
```

This writes a CloudFormation template to `aws_pipeline/cdk.out`; it does not deploy resources. Actual AWS deployment steps are in [aws-security-telemetry.md](aws-security-telemetry.md).

## Shut down and clean up

Stop each foreground process with Ctrl+C. To remove the generated local demo databases:

```powershell
Remove-Item -LiteralPath .sentinelot-demo.sqlite3, .sentinelot-ml-demo.sqlite3 -ErrorAction SilentlyContinue
```

The normal dashboard demo uses generated incident data; it does not need to start a continuous telemetry stream.
