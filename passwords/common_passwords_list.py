import csv

COMMON_PASSWORDS_PATH = "common_passwords.csv"

# Downloads a list of popular passwords from a CSV file
def load_common_passwords():
    passwords = set()
    try:
        with open(COMMON_PASSWORDS_PATH, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                passwords.add(row["password"])
    except Exception as e:
        print("Error loading popular passwords:", e)
    return passwords

COMMON_PASSWORDS = load_common_passwords()

# Checks if the password is too simple.
def is_common_password(password):
    return password in COMMON_PASSWORDS
