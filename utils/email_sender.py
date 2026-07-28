from flask_mail import Message


def send_otp(mail, recipient_email, otp):

    try:

        message = Message(
            subject="Cloud Security Project - OTP Verification",
            recipients=[recipient_email]
        )

        message.body = f"""
Hello,

Thank you for registering with the Cloud Security Project.

Your One-Time Password (OTP) is:

{otp}

This OTP is valid for 5 minutes.

If you did not request this OTP, please ignore this email.

Regards,
Cloud Security Project
"""

        mail.send(message)

        print("=" * 50)
        print("OTP Email Sent Successfully")
        print("=" * 50)

    except Exception as e:

        print("=" * 50)
        print("EMAIL ERROR")
        print(e)
        print("=" * 50)