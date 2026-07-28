import random


def generate_otp():
    """
    Generate a 6-digit OTP.
    """
    otp = ""

    for _ in range(6):
        otp += str(random.randint(0, 9))

    return otp