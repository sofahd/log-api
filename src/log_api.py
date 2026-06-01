from flask import Flask, request
from json_logger import JsonLogger
from sofahutils import load_config
import json, threading, time

app = Flask(__name__)
# Cap request bodies so a flooded or abused pot on log_net cannot bloat the log writer.
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024
config = load_config(path='/home/api/config.ini')
logger = JsonLogger(config=config)
def_answer = {
    "status": "",
    "message": "",
    "data": {},
}

# Per-source rate limit on /log. Events from one source beyond the cap within the window are
# shed to protect the writer from a flood. The cap is generous so normal attack volume is fully
# captured -- this trades some fidelity under an extreme flood for writer availability. Tune via
# a [RateLimit] config section (max / window), or set max=0 to disable.
RATE_LIMIT_MAX = config.getint('RateLimit', 'max', fallback=600)        # events per window per source ip
RATE_LIMIT_WINDOW = config.getint('RateLimit', 'window', fallback=60)   # seconds
_rate_lock = threading.Lock()
_rate_history = {}  # source ip -> list[timestamps within the window]


def within_rate_limit(ip:str) -> bool:
    """Return True if this source ip may log now (and record the hit); max<=0 disables limiting."""

    if RATE_LIMIT_MAX <= 0:
        return True
    now = time.time()
    with _rate_lock:
        hist = [t for t in _rate_history.get(ip, []) if now - t < RATE_LIMIT_WINDOW]
        if len(hist) >= RATE_LIMIT_MAX:
            _rate_history[ip] = hist
            return False
        hist.append(now)
        _rate_history[ip] = hist
        # opportunistic cleanup so the dict can't grow unbounded across many distinct sources
        if len(_rate_history) > 10000:
            for stale in [k for k, v in _rate_history.items() if not v or now - v[-1] > RATE_LIMIT_WINDOW]:
                _rate_history.pop(stale, None)
        return True


@app.route(rule='/health', methods=['GET'])
def health():
    return 'OK', 200


@app.route(rule='/log', methods=['POST'])
def log():
    """
    Implements an API endpoint to the `log` function implemented by the JsonLogger class.
    """

    resp_dict = def_answer.copy()

    req_keys = ['eventid', 'content', 'ip', 'src_port', 'dst_port']
    missing_keys = []
    
    for key in req_keys:
        if key not in request.form.keys():
            missing_keys.append(key)
    
    if len(missing_keys) > 0:
        resp_dict['status'] = 'error'
        resp_dict['message'] = f"Missing keys:"
        resp_dict['data'] = missing_keys
        return resp_dict, 400
    
    try:
        content_dict = json.loads(request.form['content'])
    except Exception as e:
        resp_dict['status'] = 'error'
        resp_dict['message'] = f"Error during jsonification of content, content has to be a dict!: {e}"
        return resp_dict, 400

    if not isinstance(content_dict, dict):
        resp_dict['status'] = 'error'
        resp_dict['message'] = "Error: content has to be a JSON object"
        return resp_dict, 400

    if not within_rate_limit(request.form.get("ip")):
        resp_dict['status'] = 'throttled'
        resp_dict['message'] = 'rate limit exceeded for source; event dropped'
        return resp_dict, 200  # 200 so the pot's logger keeps working rather than raising

    try:
        logger.log(eventid=request.form.get('eventid'), content=content_dict, ip=request.form.get("ip"), src_port=request.form.get("src_port"), dst_port=request.form.get("dst_port"), session=request.form.get("session"))
    except Exception as e:
        resp_dict['status'] = 'error'
        resp_dict['message'] = f"Error: {e}"
        return resp_dict, 400
    
    resp_dict['status'] = 'success'
    resp_dict['message'] = 'Successfully logged event'
    return resp_dict, 200


@app.route(rule="/info", methods=["POST"])
def info():
    """
    This function implements an API-Endpoint for the `info` method of the JsonLogger class.
    """

    return handle_logging(level='info', request=request)


@app.route(rule="/warn", methods=["POST"])
def warn():
    """
    This function implements an API-Endpoint for the `warn` method of the JsonLogger class.
    """

    return handle_logging(level='warn', request=request)


@app.route(rule="/error", methods=["POST"])
def error():
    """
    This function implements an API-Endpoint for the `error` method of the JsonLogger class.
    """

    return handle_logging(level='error', request=request)



def handle_logging(level:str, request:request) -> tuple[dict, int]:
    """
    This function is used to handle the logging of the API.
    :param level: The level of the log, can be `info`, `warn` or `error`.
    :type level: str
    :param request: The request object.
    :type request: request
    :return: A tuple containing the response dict and the status code.
    """
    
    resp_dict = def_answer.copy()

    req_keys = ['message', 'method', 'ip', 'src_port', 'dst_port']
    missing_keys = []
    
    for key in req_keys:
        if key not in request.form.keys():
            missing_keys.append(key)
    
    if len(missing_keys) > 0:
        resp_dict['status'] = 'error'
        resp_dict['message'] = f"Missing keys:"
        resp_dict['data'] = missing_keys
        return resp_dict, 400
    try:
        if level == 'info':
            logger.info(message=request.form.get("message"), method=request.form.get("method"), ip=request.form.get("ip"), src_port=request.form.get("src_port"), dst_port=request.form.get("dst_port"))
        elif level == 'warn':
            logger.warn(message=request.form.get("message"), method=request.form.get("method"), ip=request.form.get("ip"), src_port=request.form.get("src_port"), dst_port=request.form.get("dst_port"))
        elif level == 'error':
            logger.error(message=request.form.get("message"), method=request.form.get("method"), ip=request.form.get("ip"), src_port=request.form.get("src_port"), dst_port=request.form.get("dst_port"))
        else:
            raise ValueError(f"Invalid level: {level}")
    except Exception as e:
        resp_dict['status'] = 'error'
        resp_dict['message'] = f"Error: {e}"
        return resp_dict, 400
    
    resp_dict['status'] = 'success'
    resp_dict['message'] = 'Successfully logged event'
    return resp_dict, 200
    