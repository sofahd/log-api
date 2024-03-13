# log-api
Logging API for the SOFAH Project

## Usage
This project is not designed to be used standalone but was developed as part of the sofah project.

This projects implements a Docker Container which offers a api for logging purposes.

Log Messages are delivered as *json-lines* in a larger Json-file.

**Make sure that you have set the according permissions on the logging folder**

### Log-Format
- `timestamp`: A Unix timestamp indicating when the event occurred.
- `session`: A unique identifier for the session in which the event was logged.
- `eventid`: A string that provides an identifier for the type of event, facilitating the categorization and analysis of log entries.
- `src_ip`: The source IP address from which the interaction or attack attempt originated.
- `src_port`: The source port number used by the attacker or interacting entity.
- `dst_ip`: The destination IP address targeted by the interaction or attack, typically the IP address of the honeypot.
- `dst_port`: The destination port number on the honeypot that was accessed or attempted to be accessed.
- Additional fields may include detailed information about the event, such as the `method` used for HTTP requests, specific `data` sent by the attacker, and the `expected_status_code` for simulated responses.
