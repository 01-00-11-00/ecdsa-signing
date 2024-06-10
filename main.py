
# ---------------------------- Libraries ------------------------------- #
from utils.ecdsa_signing import EcdsaSigning
from utils.user_input_validation import UserInputValidator

# ----------------------------- Constant ------------------------------- #
SIGNING = EcdsaSigning()
INPUT_VALIDATOR = UserInputValidator()


# ---------------------------- Functions ------------------------------- #
def test_attack():
    m1 = SIGNING.read_message("test_data/message1.bin")
    m2 = SIGNING.read_message("test_data/message2.bin")
    sig1 = SIGNING.read_signature("test_data/signature1.bin")
    sig2 = SIGNING.read_signature("test_data/signature2.bin")

    result = SIGNING.check_for_identical_nonce(m1, m2, sig1, sig2)

    if result is not None:
        print()
        print("Task 3")
        print(f"Recovered key: {result}")
    else:
        print()
        print("The nonce are not identical.")


def main():
    """
    Main function of the program.
    :return: None
    """

    # Body
    test_attack()


# ------------------------------ Main ---------------------------------- #

if __name__ == "__main__":
    main()
