import string
import random
import mysql.connector
import logging

logger = logging.getLogger(__name__)


def generate_password():
    # Set of possible characters
    char = string.ascii_letters + string.punctuation + string.digits
    # Creating password of random size and displaying it
    password = "".join(random.choice(char) for i in range(25))
    return password


class GuacamoleDatabase(object):
    def __init__(self, user, password,
                 host='127.0.0.1', database='guacamole_db'):
        self.user = user
        self.password = password
        self.host = host
        self.database = database

        self._conn = mysql.connector.connect(
            user=self.user,
            password=self.password,
            host=self.host,
            database=self.database
        )

        self._cursor = self._conn.cursor()
        self._conn.autocommit = True

        logger.info("Setup connection to %s as %s", self.host, self.user)

    def is_user(self, username):
        """Check if a user exists"""
        cmd = """
            SELECT entity_id FROM guacamole_entity
            WHERE name = %s AND type = 'USER'
        """
        self._cursor.execute(cmd, (username, ))
        rows = self._cursor.fetchall()
        if len(rows) == 1:
            return True

        return False

    def create_user(self, username, name='', email='', employee_id=''):
        """Create a user who does not exist in the database"""

        create_entity = """
            -- Create base entity entry for user
            INSERT INTO guacamole_entity (name, type)
                VALUES (%(username)s, 'USER')
            ON DUPLICATE KEY UPDATE name=name
        """

        create_salt = """
            SET @salt = UNHEX(SHA2(UUID(), 256));
        """

        create_user = """
            -- Create user and hash password with salt
            INSERT INTO guacamole_user (
                entity_id,
                password_salt,
                password_hash,
                password_date,
                full_name,
                email_address,
                organization
            )
            VALUES (
                (SELECT entity_id
                    FROM guacamole_entity
                    WHERE
                        name = %(username)s
                        AND type = 'USER'
                ),
                @salt,
                UNHEX(SHA2(CONCAT(%(password)s, HEX(@salt)), 256)),
                CURRENT_TIMESTAMP,
                %(name)s,
                %(email)s,
                %(organization)s
            )
            ON DUPLICATE KEY UPDATE
                password_salt=@salt,
                password_hash=UNHEX(SHA2(
                    CONCAT(%(password)s, HEX(@salt)), 256)),
                full_name=%(name)s,
                email_address=%(email)s,
                organization=%(organization)s
        """

        data = {
            'username': username,
            'password': generate_password(),
            'email': email,
            'name': name,
            'organization': employee_id
        }

        self._cursor.execute(create_salt, data)
        self._cursor.execute(create_entity, data)
        self._cursor.execute(create_user, data)
        return True

    def delete_user(self, username):
        """Delete user from database"""
        self._cursor.execute(
            "DELETE from guacamole_entity WHERE name = (%s)", (username,))
        return self._cursor.rowcount == 1

    def _get_user_id(self, name, kind='USER'):
        """Get the ID of a user group"""
        cmd = """
        SELECT entity_id FROM guacamole_entity
        WHERE (name, type) = (%s, %s)
        """

        self._cursor.execute(cmd, (name, kind))
        rows = self._cursor.fetchall()
        if len(rows) != 1:
            return None

        return rows[0][0]

    def add_user_to_group(self, user, group):
        cmd = """
        INSERT INTO guacamole_user_group_member
            (user_group_id, member_entity_id)
            SELECT (SELECT user_group_id FROM
                guacamole_user_group WHERE entity_id =
                    (SELECT entity_id FROM guacamole_entity
                        WHERE (name = %(group)s
                        AND type = 'USER_GROUP')))
                        AS user_group_id,
                    (SELECT entity_id FROM guacamole_entity
                        WHERE (name = %(user)s
                        AND type = 'USER'))
                        AS member_entity_id
        """

        data = {'group': group, 'user': user}
        try:
            self._cursor.execute(cmd, data)
        except mysql.connector.errors.IntegrityError:
            return False

        if self._cursor.rowcount != 1:
            return False

        return True

    def remove_user_from_group(self, user, group):
        cmd = """
        DELETE FROM guacamole_user_group_member
            WHERE user_group_id =
                (SELECT user_group_id FROM guacamole_user_group
                    WHERE entity_id = (SELECT entity_id FROM guacamole_entity
                        WHERE name = %(group)s AND type = 'USER_GROUP'))
            AND member_entity_id =
                (SELECT entity_id FROM guacamole_entity WHERE name = %(user)s
                    AND type = 'USER')
        """

        data = {'group': group, 'user': user}
        self._cursor.execute(cmd, data)
        try:
            self._cursor.execute(cmd, data)
        except mysql.connector.errors.IntegrityError:
            return False

        if self._cursor.rowcount != 1:
            return False

        return True

    def create_vnc_connection(self, name, group, hostname, password, port):
        """Create a VNC connection"""
        cmd = """
        INSERT INTO guacamole_connection
        (connection_name, protocol, parent_id)
        VALUES
        (%(name)s, 'vnc',
            (SELECT connection_group_id FROM guacamole_connection_group
                WHERE connection_group_name = %(group)s
                    AND type = 'ORGANIZATIONAL' AND parent_id is NULL
            )
        );
        """
        data = {'group': group, 'name': name}
        self._cursor.execute(cmd, data)

        if self._cursor.rowcount != 1:
            return False

        connection_id = self._cursor.lastrowid

        # Create Connection Paramaters

        for vals in zip(('hostname', 'password', 'port'),
                        (hostname, password, port)):
            cmd = """
                INSERT INTO guacamole_connection_parameter
                    (connection_id, parameter_name, parameter_value)
                VALUES
                    (%(id)s, %(name)s, %(value)s)
                ON DUPLICATE KEY UPDATE
                    connection_id = %(id)s,
                    parameter_name = %(name)s,
                    parameter_value = %(value)s
            """
            data = {
                'id': connection_id,
                'name': vals[0],
                'value': vals[1]
            }
            self._cursor.execute(cmd, data)

    def get_group_members(self, group):
        """Get group members"""
        cmd = """
            SELECT name from guacamole_user_group_member
            INNER JOIN guacamole_entity ON
            (guacamole_entity.entity_id=guacamole_user_group_member.member_entity_id)
            WHERE user_group_id = (
                SELECT user_group_id FROM guacamole_user_group
                WHERE entity_id = (
                    SELECT entity_id FROM guacamole_entity
                    WHERE name = %s
                )
            )
        """

        self._cursor.execute(cmd, (group,))
        rtn = [a[0] for a in self._cursor.fetchall()]
        return rtn
