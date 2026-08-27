import csv
import random

random.seed(42)

# ============================================================
# 200 PHISHING EMAILS
# ============================================================

phishing_templates = [
    (
        "URGENT: Your {service} account has been suspended. "
        "Verify your account immediately at {url} to restore access."
    ),
    (
        "Security Alert: We detected unusual activity on your {service} account. "
        "Confirm your login information at {url}."
    ),
    (
        "Your {service} password will expire today. "
        "Reset your password immediately using {url}."
    ),
    (
        "FINAL WARNING! Your {service} account will be permanently closed "
        "unless you verify your identity at {url}."
    ),
    (
        "Your payment for {service} could not be processed. "
        "Update your payment information at {url}."
    ),
    (
        "Your bank account has been temporarily locked because of suspicious activity. "
        "Verify your account at {url} within 24 hours."
    ),
    (
        "Congratulations! You have been selected to receive a {amount} reward. "
        "Claim your prize now at {url}."
    ),
    (
        "Your {service} subscription has expired. "
        "Update your billing information immediately at {url}."
    ),
    (
        "Unauthorized transaction detected on your account. "
        "Login to confirm this transaction at {url}."
    ),
    (
        "Important: Your account requires immediate KYC verification. "
        "Submit your information through {url}."
    ),
    (
        "Your package is waiting for delivery. "
        "Pay the small delivery fee at {url} to receive your package."
    ),
    (
        "Your refund is ready to be processed. "
        "Confirm your bank details at {url}."
    ),
    (
        "Your credit card has been blocked. "
        "Verify your card information immediately at {url}."
    ),
    (
        "We noticed a new login to your account. "
        "If this was not you, secure your account at {url}."
    ),
    (
        "Your account has been flagged for security review. "
        "Confirm your password at {url} to avoid suspension."
    ),
    (
        "Immediate action required: Your online banking session has expired. "
        "Login again at {url}."
    ),
    (
        "You have won an exclusive {amount} cash prize. "
        "Click {url} to claim your reward before it expires."
    ),
    (
        "Your invoice is overdue. "
        "Make the required payment immediately using {url}."
    ),
    (
        "Your email account will be deleted today unless you verify it. "
        "Confirm your account at {url}."
    ),
    (
        "Your account security settings require an immediate update. "
        "Verify your credentials at {url}."
    ),
]

services = [
    "bank",
    "PayPal",
    "Amazon",
    "Microsoft",
    "Google",
    "Gmail",
    "Apple",
    "Netflix",
    "online banking",
    "cloud storage",
    "shopping",
    "payment"
]

urls = [
    "http://secure-account-verification.com/login",
    "http://account-security-check.com/verify",
    "http://bank-security-alert.com/login",
    "http://password-reset-confirm.com/update",
    "http://payment-verification-center.com/confirm",
    "http://secure-login-verification.com/account",
    "http://identity-check-now.com/verify",
    "http://billing-update-alert.com/payment",
    "http://refund-verification-center.com/claim",
    "http://account-unlock-service.com/login",
    "http://security-confirmation.com/verify",
    "http://online-account-check.com/login",
    "http://customer-verification-alert.com/update",
    "http://secure-payment-review.com/confirm",
    "http://delivery-fee-payment.com/pay"
]

amounts = [
    "$500",
    "$1,000",
    "$2,500",
    "₹50,000",
    "₹1,00,000",
    "$750",
    "€2,000"
]

phishing_emails = []

for i in range(200):

    template = random.choice(phishing_templates)

    email = template.format(
        service=random.choice(services),
        url=random.choice(urls),
        amount=random.choice(amounts)
    )

    # Add realistic variation
    endings = [
        "\n\nFailure to complete this request may result in account closure.",
        "\n\nPlease complete this verification as soon as possible.",
        "\n\nDo not ignore this security notification.",
        "\n\nYour immediate response is required.",
        "\n\nFailure to respond within 24 hours may result in suspension."
    ]

    email += random.choice(endings)

    phishing_emails.append(email)


# ============================================================
# 200 SAFE EMAILS
# ============================================================

safe_templates = [
    (
        "Hello {name},\n\n"
        "This is a reminder that our project meeting is scheduled "
        "for {day} at {time}.\n\n"
        "Please bring your project progress and presentation materials.\n\n"
        "Thank you,\n"
        "Project Coordinator"
    ),
    (
        "Dear {name},\n\n"
        "Your monthly account statement is now available in your "
        "official online banking portal.\n\n"
        "You can review it whenever convenient.\n\n"
        "Thank you."
    ),
    (
        "Hello Team,\n\n"
        "The weekly project meeting will be held on {day} at {time}.\n\n"
        "Please prepare your updates before the meeting.\n\n"
        "Regards,\n"
        "Project Team"
    ),
    (
        "Hi {name},\n\n"
        "Thank you for attending today's workshop. "
        "The presentation materials will be shared with participants.\n\n"
        "Best regards,\n"
        "Training Team"
    ),
    (
        "Dear Customer,\n\n"
        "Your payment of {amount} has been successfully received.\n\n"
        "No further action is required.\n\n"
        "Thank you for using our service."
    ),
    (
        "Hello {name},\n\n"
        "Your appointment with the service center is confirmed for {day}.\n\n"
        "Please arrive a few minutes before your scheduled time.\n\n"
        "Thank you."
    ),
    (
        "Dear Student,\n\n"
        "Your examination timetable has been published on the college portal.\n\n"
        "Please check the schedule before your examinations.\n\n"
        "Academic Office"
    ),
    (
        "Hi Team,\n\n"
        "Today's software deployment was completed successfully.\n\n"
        "The application is now available for normal testing.\n\n"
        "Regards,\n"
        "Development Team"
    ),
    (
        "Hello {name},\n\n"
        "Please find the updated project report attached for your review.\n\n"
        "We can discuss the remaining items during our next meeting.\n\n"
        "Regards."
    ),
    (
        "Dear Customer,\n\n"
        "Your recent order has been successfully delivered to the registered address.\n\n"
        "Thank you for shopping with us."
    ),
    (
        "Hello {name},\n\n"
        "Your course registration has been successfully completed.\n\n"
        "You can view your course schedule through the student portal.\n\n"
        "Regards,\n"
        "Administration"
    ),
    (
        "Hi {name},\n\n"
        "This is a reminder about your scheduled appointment tomorrow.\n\n"
        "Please contact our office if you need to change the appointment time.\n\n"
        "Thank you."
    ),
    (
        "Dear Employee,\n\n"
        "Your annual leave balance has been updated in the employee portal.\n\n"
        "You can review your current balance when convenient.\n\n"
        "HR Department"
    ),
    (
        "Hello everyone,\n\n"
        "Please remember to submit your assignments before Friday.\n\n"
        "If you have any questions, contact your instructor.\n\n"
        "Thank you."
    ),
    (
        "Dear Customer,\n\n"
        "Your support request has been received and assigned to our service team.\n\n"
        "We will respond during normal business hours.\n\n"
        "Customer Support"
    ),
    (
        "Hi {name},\n\n"
        "Congratulations on completing your training program.\n\n"
        "Your completion record has been updated successfully.\n\n"
        "Best wishes."
    ),
    (
        "Hello Team,\n\n"
        "The meeting minutes have been uploaded to the shared project folder.\n\n"
        "Please review them before the next discussion.\n\n"
        "Regards."
    ),
    (
        "Dear Customer,\n\n"
        "Your subscription renewal was completed successfully.\n\n"
        "Your service will continue normally.\n\n"
        "Thank you."
    ),
    (
        "Hello {name},\n\n"
        "Your application has been received and is currently under review.\n\n"
        "We will contact you when the review is complete.\n\n"
        "Regards."
    ),
    (
        "Hi Team,\n\n"
        "The presentation slides for tomorrow's seminar are ready.\n\n"
        "Please review the slides before the session.\n\n"
        "Thank you."
    ),
]

names = [
    "Anil",
    "Priya",
    "Rahul",
    "Sarah",
    "David",
    "Kavitha",
    "John",
    "Meena",
    "Arun",
    "Sneha"
]

days = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday"
]

times = [
    "9:00 AM",
    "10:00 AM",
    "11:30 AM",
    "2:00 PM",
    "3:30 PM",
    "4:00 PM"
]

safe_emails = []

for i in range(200):

    template = random.choice(safe_templates)

    email = template.format(
        name=random.choice(names),
        day=random.choice(days),
        time=random.choice(times),
        amount=random.choice([
            "₹1,500",
            "₹2,500",
            "₹5,000",
            "$50",
            "$100"
        ])
    )

    safe_emails.append(email)


# ============================================================
# SHUFFLE DATA
# ============================================================

dataset = []

for email in phishing_emails:
    dataset.append([
        email,
        "Phishing"
    ])

for email in safe_emails:
    dataset.append([
        email,
        "Safe"
    ])

random.shuffle(dataset)


# ============================================================
# SAVE CSV
# ============================================================

with open(
    "email.csv",
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.writer(file)

    writer.writerow([
        "text",
        "label"
    ])

    writer.writerows(dataset)


# ============================================================
# RESULT
# ============================================================

print("=" * 70)
print("              DATASET CREATED SUCCESSFULLY")
print("=" * 70)

print()
print("Total emails : 400")
print("Phishing     : 200")
print("Safe         : 200")
print()
print("Created file : email.csv")
print("=" * 70)