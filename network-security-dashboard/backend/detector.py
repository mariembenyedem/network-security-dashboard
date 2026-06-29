import sqlite3

THRESHOLD = 20

def detect(ip, count):

    if count > THRESHOLD:

        print("Suspicious activity:", ip)

        save_alert(ip, "Suspicious activity: too many packets")


def save_alert(ip, message):

    connection = sqlite3.connect("database/security.db")

    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO alerts (ip, alert) VALUES (?, ?)",
        (ip, message)
    )

    connection.commit()

    connection.close()


if __name__ == "__main__":

    save_alert("9.9.9.9", "Test alert")

    print("test alert saved")