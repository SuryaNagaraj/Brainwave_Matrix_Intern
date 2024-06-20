import re

# Sample list of common passwords for demonstration
COMMON_PASSWORDS = [
    '123456', 'password', '123456789', '12345678', '12345', '1234567',
    'qwerty', 'abc123', 'password1', 'admin', 'letmein', 'welcome'
]
def check_common_patterns(password):
    """Check for common patterns or dictionary words in the password."""
    if password.lower() in COMMON_PASSWORDS:
        return -30
    patterns = ['1234', 'abcd', 'qwerty', 'password', 'admin']
    for pattern in patterns:
        if pattern in password.lower():
            return -20
    return 0


def password_strength(password):
    """Assess the strength of a given password."""
    score = 0
    feedback = []

    # Length check
    length = len(password)
    if length < 8:
        feedback.append("Password is too short.")
        score -= 20
    elif length <= 12:
        feedback.append("Password length is okay, but longer is better.")
        score += 10
    else:
        feedback.append("Password length is good.")
        score += 20

    # Complexity check
    if re.search(r'[a-z]', password):
        score += 10
    else:
        feedback.append("Add lowercase letters for a stronger password.")

    if re.search(r'[A-Z]', password):
        score += 10
    else:
        feedback.append("Add uppercase letters for a stronger password.")

    if re.search(r'[0-9]', password):
        score += 10
    else:
        feedback.append("Add digits for a stronger password.")

    if re.search(r'[@$!%*?&#]', password):
        score += 10
    else:
        feedback.append("Add special characters (e.g., @$!%*?&#) for a stronger password.")

    # Uniqueness check
    uniqueness_deduction = check_common_patterns(password)
    if uniqueness_deduction < 0:
        feedback.append("Avoid common patterns and dictionary words.")
    score += uniqueness_deduction

    # Final assessment
    if score >= 40:
        feedback.append("Your password is strong.")
    elif score >= 20:
        feedback.append("Your password is moderate. Consider making it stronger.")
    else:
        feedback.append("Your password is weak. Please create a stronger password.")

    return score, feedback


def main():
    """Main function to interact with the user and assess password strength."""
    print("Password Strength Assessment Tool")
    password = input("Enter your password: ")
    score, feedback = password_strength(password)

    print(f"\nPassword Score: {score}")
    print("Feedback:")
    for comment in feedback:
        print(f" - {comment}")


if __name__ == "__main__":
    main()