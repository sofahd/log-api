from utils.utils import load_var_from_config_and_validate, save_as_json, load_json_file_to_dict, get_own_ip
import configparser, time, hashlib, pytz, json
from datetime import datetime
from typing import Optional
from utils.exceptions import PathIsNoFileException

class JsonLogger:
    """
    Logger class to implement the specific required json logging.
    """

    def __init__(self, config:configparser.ConfigParser) -> None:
        """
        Constructor for the JsonLogger Class.
        :param config: config
        :type config: configparser.ConfigParser
        """
        
        self.path = load_var_from_config_and_validate(config=config, section='Paths', option='logging_folder_path')
        self.sessions = []
        self.dst_ip = get_own_ip(config=config)



    def log(self, eventid:str, content:dict, ip:str, src_port:int, dst_port:int):
        """
        This method is for logging an event.
        :param eventid: The id of the event should look like `sofah.honeypot.static_endpoint`
        :type eventid: str
        :param content: a dictionary containing the content
        :type content: dict
        :param ip: ip-adress of the source
        :type ip: str
        :param src_port: source port
        :type src_port: int
        :param dst_port: destination port
        :type dst_port: int
        """
        
        try:
            self.sessions = load_json_file_to_dict(path=f"{self.path}/sessions.json")
        except PathIsNoFileException:
            self.sessions = []
        except json.decoder.JSONDecodeError:
            self.sessions = []

        if type(self.sessions) != list:
            self.sessions = []

        key = self.check_if_event_exists(ip)
        if key == None:
            key = self.generate_session_id(ip=ip)

        if key not in self.sessions:
            self.sessions.append(key)

        content['src_ip'] = ip
        content['session'] = key
        content['timestamp'] = self.get_formatted_timestamp()
        content['eventid'] = eventid
        content['src_port'] = src_port
        content['dst_ip'] = self.dst_ip
        content['dst_port'] = dst_port

        filename = "sofah_log"
        
        save_as_json(f"{self.path}/{filename}.json", content=content, mode='a', newline=True)
        save_as_json(f"{self.path}/sessions.json", content=self.sessions)

    def warn(self, message:str, method:str, ip:str, src_port:int, dst_port:int):
        """
        used to replace the `.warn()`-Function implemented by the standard logger.
        :param message: logmessage you want to log
        :type message: str
        :param method: the method or function or class you want to specify to clarify where the message occured.
        :type method: str
        :param ip: specify the source ip
        :type ip: str
        :param src_port: specify the source port
        :type src_port: int
        :param dst_port: specify the destination port
        :type dst_port: int
        """

        self.log(eventid=f'sofah_pot.{method}.warn', content={"message": message}, ip=ip, src_port=src_port, dst_port=dst_port)

    
    def info(self, message:str, method:str, ip:str, src_port:int, dst_port:int):
        """
        used to replace the `.info()`-Function implemented by the standard logger.
        :param message: logmessage you want to log
        :type message: str
        :param method: the method or function or class you want to specify to clarify where the message occured.
        :type method: str
        :param ip: specify the source ip
        :type ip: str
        :param src_port: specify the source port
        :type src_port: int
        :param dst_port: specify the destination port
        :type dst_port: int
        """

        self.log(eventid=f'sofah_pot.{method}.info', content={"message": message}, ip=ip, src_port=src_port, dst_port=dst_port)


    def error(self, message:str, method:str, ip:str, src_port:int, dst_port:int):
        """
        used to replace the `.error()`-Function implemented by the standard logger.
        :param message: logmessage you want to log
        :type message: str
        :param method: the method or function or class you want to specify to clarify where the message occured.
        :type method: str
        :param ip: specify the source ip
        :type ip: str
        :param src_port: specify the source port
        :type src_port: int
        :param dst_port: specify the destination port
        :type dst_port: int
        """

        self.log(eventid=f'sofah_pot.{method}.error', content={"message": message}, ip=ip, src_port=src_port, dst_port=dst_port)


    def get_formatted_timestamp(self)->str:
        """
        Helper Method to return a properly formatted timestamp.
        :return: String containing the timestamp
        """

        timezone = pytz.timezone('Europe/Berlin')
        dt = datetime.now(timezone)
        
        return dt.strftime('%Y-%m-%d %H:%M:%S %z')

    def check_if_event_exists(self, ip:str)->Optional[str]:
        """
        This method is designed to allow to check if a hash for an event exists
        :param ip: source ip adress
        :type ip: str
        :return: either None or the preexisting string.
        """

        final_key = None
        
        for key in self.sessions:
            if self.validate_hash_func(ip=ip, hash=key):
                final_key = key

        return final_key


    def generate_session_id(self, ip:str, h_minus:int = 0)->str:
        """
        Method to generate a session id.
        :param ip: the source IP the session id should be generated for
        :type ip: str
        :param h_minus: the amount of hours the hash should be calculated in the past
        :type h_minus: int
        :return: the str containing the hash
        """

        hour_timestamp = int(time.time() / 3600) - h_minus

        string_to_be_hashed = f"{hour_timestamp}{ip}".encode()

        session_id = hashlib.sha1(string_to_be_hashed).hexdigest()[:16]

        return session_id
    
    def validate_hash_func(self, ip:str, hash:str)->bool:
        """
        Method to check validity of hash.
        :param ip: the source ip the hash should be generated for
        :type ip: str
        :param hash: the Hash that should be validated
        :type hash: str
        :return: bool indicating the validity
        """
        
        return self.generate_session_id(ip=ip) == hash or self.generate_session_id(ip=ip, h_minus=1) == hash