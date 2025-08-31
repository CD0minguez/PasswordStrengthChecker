from strengthChecker import password_strength, check_pwned

if __name__ == "__main__":
    pwd = input("Enter a password: ")

    # Check strength
    print("Strength:", password_strength(pwd))

    # Check if breached
    count = check_pwned(pwd)
    if count:
        print(f"⚠️ This password has been seen {count} times in breaches!")
    else:
        print("✅ This password has not been found in known breaches.")
