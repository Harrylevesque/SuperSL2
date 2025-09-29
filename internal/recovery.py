import random, hashlib, json

txt_path = "internal/wordlist.txt"

def select_words(wordlist_path, num_words):
    with open(wordlist_path, "r") as f:
        words = [line.strip() for line in f if line.strip()]
    return random.sample(words, num_words)

def create_passphrase(words):
    return "-".join(words)

def checksum_passphrase(passphrase):
    return hashlib.sha256(passphrase.encode()).hexdigest()

def save_checksum(userfile_path, checksum):
    with open(userfile_path, "r") as f:
        userfile = json.load(f)
    userfile["keychain"]["passphrase_checksum"] = checksum
    with open(userfile_path, "w") as f:
        json.dump(userfile, f, indent=4)

def generate_passphrase(txt_path, num_words, userfile_path):
    words = select_words(txt_path, num_words)
    passphrase = create_passphrase(words)
    checksum = checksum_passphrase(passphrase)
    save_checksum(userfile_path, checksum)
    return passphrase





def checksum_checker(userUUID, entered_words):
    try:
        entered_words = hashlib.sha256(entered_words.encode()).hexdigest()
        with open(f"storage/user/{userUUID}.json", "r") as f:
            userfile = json.load(f)
        openeduserfile_checksum = userfile["keychain"]["passphrase_checksum"]
        return {"match": entered_words == openeduserfile_checksum}
    except Exception as e:
        return {"error": str(e)}
