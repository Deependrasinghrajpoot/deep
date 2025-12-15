import random
import string

def generate_password(length, use_letters=True, use_digits=True, use_symbols=True):
    """Generate a random password based on user preferences."""
    character_pool = ""

    if use_letters:
        character_pool += string.ascii_letters
    if use_digits:
        character_pool += string.digits
    if use_symbols:
        character_pool += string.punctuation

    if not character_pool:
        raise ValueError("At least one character type must be selected!")

    password = ''.join(random.choice(character_pool) for _ in range(length))
    return password


def main():
    print("🔐 Random Password Generator 🔐")
    
    # Get password length
    while True:
        try:
            length = int(input("Enter password length (e.g., 8–50): "))
            if length < 4:
                print("Password should be at least 4 characters long for security.")
                continue
            break
        except ValueError:
            print("Please enter a valid number.")

    # Ask user for character type preferences
    use_letters = input("Include letters? (y/n): ").strip().lower() == 'y'
    use_digits = input("Include digits? (y/n): ").strip().lower() == 'y'
    use_symbols = input("Include symbols? (y/n): ").strip().lower() == 'y'

    try:
        password = generate_password(length, use_letters, use_digits, use_symbols)
        print("\n✅ Generated Password:", password)
    except ValueError as e:
        print("Error:", e)


if __name__ == "__main__":
    main()
