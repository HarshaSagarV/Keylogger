import os

# Suspicious network protocols
critical_protocols = [
    "tcp",
    "udp",
    "icmp",
]

# Critical permissions
important_permissions = [
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
]

# Keywords related to keyloggers
keyword_to_look_for = [
    "type",
    "keeper"
    "key",
    "logger",
    "log",
]

def is_suspicious_app(app_details):

    # Check if any of the suspicious keywords exist in the app details
    if any(keyword in app_details for keyword in keyword_to_look_for):
        return True
    # Check if the app has any of the important permissions
    for permission in important_permissions:
        if permission in app_details:
            return True
    # Check if the app has permission to access fine or coarse location
    if "android.permission.ACCESS_FINE_LOCATION" in app_details:
        return True
    if "android.permission.ACCESS_COARSE_LOCATION" in app_details:
        return True
    # Check if the app has any of the critical protocols permissions
    for protocol in critical_protocols:
        if f"android.permission.{protocol}" in app_details:
            return True
    # If none of the above conditions are met, the app is not suspicious
    return False

def detect_keyloggers():
    """Detect keylogger apps on the connected device."""
    suspicious_apps = []
    # Getting a list of all installed packages on the device
    app_list = os.popen("adb shell pm list packages").readlines()

    for app in app_list:
        # Extract the package name from the output of "pm list packages"
        app_name = app.replace('package:', '').strip()
        # Skip packages from known vendors that are not suspicious
        if "oneplus" in app_name or "qualcomm" in app_name or "google" in app_name or "oplus" in app_name or "android" in app_name:
            continue
        # Get details of the package using "dumpsys package"
        app_details = os.popen("adb shell dumpsys package " + app_name).read()
        # Check if the app is suspicious
        if is_suspicious_app(app_details):
            # If the app is suspicious, add it to the list
            suspicious_apps.append(app_name)

    if suspicious_apps:
        # If suspicious apps are found, print them and store them in a text file
        print("Suspicious applications detected on the device:")
        for app in suspicious_apps:
            print(app)
        with open("suspicious_apps.txt", "w") as f:
            f.write("\n".join(suspicious_apps))

# Call the detect_keyloggers function to start the detection process
detect_keyloggers()
