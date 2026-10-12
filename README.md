# TCN Fault Telemetry Gateway

Records faults on the transmission grid, classifies them by duration, detects cascading faults and shows grid status on a live dashboard.

## Setup
1. Create a Supabase project and run `schema.sql` in the SQL editor.
2. Put the project URL and anon key into the two constants at the top of the script in `index.html`.
3. Push to GitHub and deploy on Netlify.

## How it works
- `POST /rest/v1/rpc/ingest_fault` is the ingest endpoint (line_id, event_time, duration_ms). All times are UTC.
- Bands: transient < 100 ms, short 100 ms to under 1 s, sustained 1 s to 60 s, persistent > 60 s.
- Cascading: faults on 2 or more different lines within 5 seconds of each other.
- Severity = band weight (1 to 4) x number of affected lines.
- Faults cannot be edited or deleted (database trigger).

## Security
`search_faults_unsafe` shows the injection (`1 or 1=1`). `search_faults` is the patched version.

## Research and citations
Add the sources you actually read here (TCN grid operations, fault types, cascading fault definition, SCADA basics), with title, publisher and date.
