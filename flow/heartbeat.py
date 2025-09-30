from json import *
import os
import time
import sys
from main import *

def create_heartbeat(userUUID, kchin, pubk, serverUUID):
    heartbeat_content = {
        "status": "alive",
        "timestamp": int(time.time()),
        "userUUID": userUUID,
        "serverUUID": serverUUID,


        "is_login": "",
        "is_maintain": "",
        "is_recovery": "",
        "is_adddevice": "",
        "is_remove_device": "",
        "is_checksum": "",
        "is_get_devicedata": "",

        "datachecksum": "",

        "service": {
            "is_service": "",
            "is_add_service": "",
            "is_remove_service": "",
            "is_link_service": "",
            "is_unlink_service": "",
            "is_check_service": "",
        },
        "is_other": "",
        "keychain": kchin,
        "pubk": pubk,
    }
    return heartbeat_content


