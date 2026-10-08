ShdGuard - passive defensive monitor (By Aryan / @EPureNest)

START
  Windows: double-click ShdRun.bat (Run as administrator enables failed-logon monitoring)
  Linux/macOS: ./ShdRun.sh
  Pipeline test with a synthetic incident: ShdRun.bat --selftest   (or ./ShdRun.sh --selftest)
  Health check: add --diagnose

OPTIONAL ENVIRONMENT VARIABLES (never written to disk)
  SHD_ABUSEIPDB_KEY   AbuseIPDB key (free tier: 1,000 checks/day)
  SHD_GREYNOISE_KEY   GreyNoise Community key (strict quotas; results are cached)
  SHD_VT_KEY          VirusTotal key, hash lookups only (public API: 4/min, 500/day, not for commercial use)
  SHD_NTFY_TOPIC      phone push via the ntfy app; use a random 16+ character topic and treat it as a password
  SHD_NTFY_URL        self-hosted ntfy server (https only); default https://ntfy.sh
  HTTPS_PROXY         route lookups through your proxy

FILES
  data/shd.db               state, baseline, dedupe history, enrichment cache
  data/shd.log              activity log
  evidence/incident_N.json  hash-sealed incident record (record_sha256 verifies it)
  evidence/report_N.txt     draft abuse report; you review it and send it yourself

WHAT IT DOES NOT DO
  No hack-back, no scanning or probing of attacker hosts, no uploads of your files, no automatic reports,
  no identity lookup. Public data attributes an IP to its network operator. Identifying a person needs
  legal process through that operator and the police or national CERT.

LIMITS
  The first run treats current listening ports as the baseline. If the PC was already compromised, review
  the baseline_ports value in data/shd.db. Phone-side monitoring is not included (phone receives alerts only).
  To move the folder, delete .venv and run the launcher again.
