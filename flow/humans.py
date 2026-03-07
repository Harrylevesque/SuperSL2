import dotenv
import os




def humans():
    dotenv.load_dotenv()

    hrn = os.getenv("SERVICE_NAME")
    serviceip = os.getenv("host")
    contact = os.getenv("CONTACT_EMAIL")
    description = os.getenv("SERVICE_DESCRIPTION")

    humans_info = {
        "human_readable_name": hrn,
        "service_ip": serviceip,
        "contact_email": contact,
        "description": description,
    }
    return humans_info

if __name__ == "__main__":
    info = humans()
    print(info)