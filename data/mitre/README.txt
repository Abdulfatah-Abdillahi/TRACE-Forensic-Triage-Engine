MITRE ATT&CK data
=================
TRACE works out of the box using a small built-in table of common techniques.
For the COMPLETE ATT&CK enterprise set, download the official STIX bundle into
this folder (one time, ~30 MB):

  curl -L -o enterprise-attack.json \
    https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

Once enterprise-attack.json is present, mitre.py loads it automatically.
