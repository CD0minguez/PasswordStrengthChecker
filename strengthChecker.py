import re
import hashlib
import requests

def password_strength(password):
    score = 0
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1

    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[@$!%*?&]', password):
        score += 1

    if has_invalid_chars(password):
        return "Invalid characters ❌"
    if score <= 2:
        return "Weak ❌"
    elif score == 3:
        return "Medium ⚠️"
    else:
        return "Strong ✅"

def has_invalid_chars(password):
    allowed_pattern = r'^[A-Za-z0-9@$!%*?&]+$'
    return not re.match(allowed_pattern, password)

def get_sha1(password):
    return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

def check_pwned(password):
    sha1 = get_sha1(password)
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"Error fetching: {response.status_code}")
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0
