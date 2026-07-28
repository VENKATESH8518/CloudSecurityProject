import sqlite3
from sqlite3 import Error
from config import Config


def create_connection():
    """
    Create a connection to the SQLite database.
    """

    connection = None

    try:
        connection = sqlite3.connect(
            Config.DATABASE,
            check_same_thread=False
        )

        connection.row_factory = sqlite3.Row

        return connection

    except Error as e:

        print("Database Connection Error:", e)

        return None


def execute_query(query, parameters=()):
    """
    Execute INSERT, UPDATE, DELETE queries.
    """

    connection = create_connection()

    if connection is None:
        return False

    try:

        cursor = connection.cursor()

        cursor.execute(query, parameters)

        connection.commit()

        return True

    except Error as e:

        print("Database Error:", e)

        return False

    finally:

        connection.close()


def execute_insert(query, parameters=()):

    connection = create_connection()

    if connection is None:
        return None

    try:

        cursor = connection.cursor()

        cursor.execute(query, parameters)

        connection.commit()

        last_id = cursor.lastrowid

        return last_id

    except Error as e:

        print("Database Error:", e)

        return None

    finally:

        connection.close()




def fetch_one(query, parameters=()):
    """
    Fetch a single record.
    """

    connection = create_connection()

    if connection is None:
        return None

    try:

        cursor = connection.cursor()

        cursor.execute(query, parameters)

        row = cursor.fetchone()

        return row

    except Error as e:

        print("Database Error:", e)

        return None

    finally:

        connection.close()


def fetch_all(query, parameters=()):
    """
    Fetch all matching records.
    """

    connection = create_connection()

    if connection is None:
        return []

    try:

        cursor = connection.cursor()

        cursor.execute(query, parameters)

        rows = cursor.fetchall()

        return rows

    except Error as e:

        print("Database Error:", e)

        return []

    finally:

        connection.close()