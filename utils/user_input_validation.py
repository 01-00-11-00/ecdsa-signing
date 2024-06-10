
# ---------------------------- User Input Validator ------------------------------- #

class UserInputValidator:

    # Methods
    @staticmethod
    def validate_int_input(prompt: str) -> int:
        """
        Validate the user input for an integer.
        :param str prompt: The prompt message to display to the user.
        :return: The validated integer input from the user.
        """
        while True:
            user_input = input(prompt)

            try:
                value = int(user_input)

                if value <= 0:
                    raise ValueError("Invalid Input: Please enter a positive number.")
                break

            except ValueError:
                print("Invalid Input: Please enter a positive number.")

        return value

    @staticmethod
    def validate_float_input(prompt: str) -> float:
        """
        Validate the user input for a float.
        :param str prompt: The prompt message to display to the user.
        :return: The validated float input from the user.
        """
        while True:
            user_input = input(prompt)

            try:
                value = float(user_input)

                if value <= 0.0:
                    raise ValueError("Invalid Input: Please enter a positive number.")
                break

            except ValueError:
                print("Invalid Input: Please enter a positive number.")

        return value

    @staticmethod
    def validate_string_input(prompt: str) -> str:
        """
        Validate the user input for a string.
        :param str prompt: The prompt message to display to the user.
        :return: The validated string input from the user.
        """
        while True:
            user_input = input(prompt)

            if not user_input.strip():
                print("Invalid Input: Please enter a non-empty string.")

            else:
                break

        return user_input
