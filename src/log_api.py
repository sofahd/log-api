from flask import Flask, request
from json_logger import JsonLogger
from utils.utils import load_config
import json

app = Flask(__name__)
config = load_config(path='/home/api/config.ini')
logger = JsonLogger(config=config)
def_answer = {
    "status": "",
    "message": "",
    "data": {},
}


@app.route(rule='/health', methods=['GET'])
def health():
    return 'OK', 200


@app.route(rule='/log', methods=['POST'])
def log():
    """
    Implements an API endpoint to the `log` function implemented by the JsonLogger class.
    """

    resp_dict = def_answer.copy()

    port = request.form.get('port', 0)
    ip = request.form.get('ip', '127.0.1.1')

    req_keys = ['eventid', 'content']
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
    try:
        logger.log(eventid=request.form['eventid'], content=content_dict, ip=ip, port=port)
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

    port = request.form.get('port', 0)
    ip = request.form.get('ip', '127.0.1.1')
    method = request.form.get('method', 'generic')

    if 'message' not in request.form.keys():
        resp_dict['status'] = 'error'
        resp_dict['message'] = f"Missing key: message"
        return resp_dict, 400
    else:
        message = request.form['message']
    
    try:
        if level == 'info':
            logger.info(message=message, method=method, ip=ip, port=port)
        elif level == 'warn':
            logger.warn(message=message, method=method, ip=ip, port=port)
        elif level == 'error':
            logger.error(message=message, method=method, ip=ip, port=port)
        else:
            raise ValueError(f"level must be one of ['info', 'warn', 'error']")
    
    except Exception as e:
        resp_dict['status'] = 'error'
        resp_dict['message'] = f"Error: {e}"
        return resp_dict, 400
    
    resp_dict['status'] = 'success'
    resp_dict['message'] = 'Successfully logged event'
    return resp_dict, 200
    