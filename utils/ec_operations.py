

# ---------------------------- Elliptic Curve Operations ------------------------------- #

class EllipticCurveOperations:

    # Constructor
    def __init__(self, field, a, b):
        """
        Initializes the EllipticCurveOperations class with the given field, a, and b values.

        :param field: The field over which the elliptic curve is defined.
        :param a: The 'a' coefficient in the elliptic curve equation.
        :param b: The 'b' coefficient in the elliptic curve equation.
        """

        self.field = field
        self.a = a
        self.b = b

    # Methods
    def extended_euclidean_algorithm(self, b: int, a=None) -> tuple[int, int, int]:
        """
        Implements the extended Euclidean algorithm.

        :param a: Optional. The field to calculate the multiplicative inverse in.
        :param b: The integer to find the multiplicative inverse of.
        :return: A tuple containing the greatest common divisor, and the coefficients of Bézout's identity.
        """

        if a is None:
            a = self.field

        original_a = a
        x, y = 0, 1
        x_prev, y_prev = 1, 0

        while b != 0:
            quotient = a // b
            a, b = b, a % b
            x, x_prev = x_prev - quotient * x, x
            y, y_prev = y_prev - quotient * y, y

        # Ensure x_prev is the positive modular inverse
        if x_prev < 0 or y_prev < 0:
            x_prev += original_a

        return a, x_prev, y_prev

    def __slope(self, p1: tuple[int, int], p2: tuple[int, int]) -> int:
        """
        Calculates the slope of the line through points p1 and p2 on the elliptic curve.

        :param p1: The first point on the elliptic curve.
        :param p2: The second point on the elliptic curve.
        :return: The slope of the line through p1 and p2.
        """

        if p1 == p2:
            slope = ((3 * p1[0] ** 2 + self.a) * self.extended_euclidean_algorithm(2 * p1[1])[2]) % self.field
            return slope

        else:
            slope = ((p2[1] - p1[1]) * self.extended_euclidean_algorithm((p2[0] - p1[0]) % self.field)[2]) % self.field
            return slope

    def add(self, p1: tuple[int, int], p2: tuple[int, int]) -> tuple[int, int]:
        """
        Adds two points on the elliptic curve.

        :param p1: The first point to add.
        :param p2: The second point to add.
        :return: The result of adding p1 and p2 on the elliptic curve.
        """

        if p1 == (0, 0):
            return p2

        if p2 == (0, 0):
            return p1

        if p1[0] == p2[0] and p1[1] != p2[1]:
            return 0, 0

        s = self.__slope(p1, p2)
        x = (s ** 2 - p1[0] - p2[0]) % self.field
        y = (s * (p1[0] - x) - p1[1]) % self.field

        return x, y

    def multiply(self, p: tuple[int, int], c: int) -> tuple[int, int]:
        """
        Multiplies a point on the elliptic curve by a scalar.

        :param p: The point to multiply.
        :param c: The coefficient to multiply the point by.
        :return: The result of multiplying the point by the scalar.
        """

        bin_c = bin(c)[3:]
        result = p

        for bit in bin_c:
            result = self.add(result, result)

            if bit == "1":
                result = self.add(result, p)

        return result

    def get_order(self, p: tuple[int, int]) -> int:
        """
        Calculates the order of the point p on the elliptic curve.

        :param p: The point to calculate the order of.
        :return: The order of the point p.
        """

        order = 1
        current = p

        while current != (0, 0):
            current = self.add(current, p)
            order += 1

        return order

    def mirrored_point(self, p: tuple[int, int]) -> tuple[int, int]:
        """
        Calculates the inverse of a point on the elliptic curve.

        :param p: The point to calculate the inverse of.
        :return: The inverse of the point p.
        """

        return p[0], -p[1] % self.field

    def get_inverse(self, p: tuple[int, int]) -> tuple[int, int]:
        if p[1] == 0:
            return p[0], p[1]

        inv_y = self.field - p[1]
        return p[0], inv_y

