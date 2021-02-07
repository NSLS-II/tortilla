import string
import random
import mysql.connector
import logging

from mysql.connector import connection

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

    def _is_entity(self, username, entity):
        """Check if a user exists"""
        data = {'name': username, 'entity': entity}

        cmd = """
            SELECT entity_id FROM guacamole_entity
            WHERE name = %(name)s AND type = %(entity)s
        """

        self._cursor.execute(cmd, data)
        rows = self._cursor.fetchall()
        if len(rows) != 0:
            return True

        return False

    def is_user(self, username):
        """Check if a user exists"""
        return self._is_entity(username, 'USER')

    def is_group(self, groupname):
        """Check if a user group exists"""
        return self._is_entity(groupname, 'USER_GROUP')

    def create_user(self, username, name='', email='', employee_id=''):
        """Create a user who does not exist in the database"""

        create_entity = """
            -- Create base entity entry for user
            INSERT INTO guacamole_entity (name, type)
                VALUES (%(username)s, 'USER')
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

        # First lets check if we have a valid entity ID

        if not self.is_user(username):
            logging.info("Creating user '%s'", username)
            self._cursor.execute(create_entity, data)
        else:
            logging.info("User '%s' exists in database", username)

        self._cursor.execute(create_salt, data)
        self._cursor.execute(create_user, data)
        return True

    def create_user_group(self, name):
        """Create a Guacamole User Group"""
        data = {'name': name}

        create_entity = """
            -- Create base entity entry for user
            INSERT INTO guacamole_entity (name, type)
                VALUES (%(name)s, 'USER_GROUP')
        """
        create_group = """
            -- Create user and hash password with salt
            INSERT INTO guacamole_user_group (
                entity_id
            )
            VALUES (
                (SELECT entity_id
                    FROM guacamole_entity
                    WHERE
                        name = %(name)s
                        AND type = 'USER_GROUP'
                )
            )
            ON DUPLICATE KEY UPDATE
            entity_id=entity_id
        """

        if not self.is_group(name):
            logging.info("Creating Group '%s'", name)
            self._cursor.execute(create_entity, data)
            self._cursor.execute(create_group, data)
        else:
            logging.info("Group '%s' exists", name)

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
            logging.warning("No data or wrong data returned getting ID")
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
            logging.debug("Data error adding user to group, already there")
            return False

        if self._cursor.rowcount != 1:
            logging.critical("Failed to add row to database for group"
                             " addition")
            return False

        logging.debug("Added user %s to group %s",
                      user, group)
        return True

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
        if self._cursor.rowcount != 1:
            logging.warning("User %s was not in group %s",
                            user, group)
            return False

        logging.debug("Removed user %s from group %s", user, group)

        return True

    def create_vnc_connection(self, name, group, parent,
                              hostname, password, port):
        """Create a VNC connection"""

        data = {
            'group': group,
            'name': name,
            'parent': parent,
            'protocol': 'vnc'
        }

        if parent is not None:
            cmd = """
                SELECT connection_group_id from guacamole_connection_group
                WHERE
                connection_group_name = %(parent)s
                AND
                type =  'ORGANIZATIONAL'
                AND
                parent_id IS NULL
            """

            self._cursor.execute(cmd, data)
            rows = self._cursor.fetchall()
            if self._cursor.rowcount != 1:
                return False

            data['parent'] = rows[0][0]

        else:
            data['parent'] = 'NULL'

        logging.debug("Connection Parent = %s", data['parent'])

        cmd = """
        INSERT INTO guacamole_connection
        (connection_name, protocol, parent_id)
        VALUES
        (%(name)s, 'vnc',
            (SELECT connection_group_id FROM guacamole_connection_group
                WHERE connection_group_name = %(group)s
                    AND type = 'ORGANIZATIONAL' AND parent_id = %(parent)s
            )
        )
        ON DUPLICATE KEY UPDATE
            connection_name = VALUES (connection_name)
        """

        logging.debug("Creating connection name = '%s' "
                      "protocol = '%s' parent = '%s'",
                      data['name'], data['protocol'], data['parent'])

        self._cursor.execute(cmd, data)

        if self._cursor.rowcount != 1:
            cmd = """
                SELECT connection_id FROM guacamole_connection
                WHERE (
                    connection_name = %(name)s AND
                    protocol = %(protocol)s AND
                    parent_ID = (
                        (SELECT connection_group_id FROM guacamole_connection_group
                            WHERE connection_group_name = %(group)s
                                AND type = 'ORGANIZATIONAL' AND parent_id = %(parent)s
                        )
                    )
                )
            """
            self._cursor.execute(cmd, data)
            rows = self._cursor.fetchall()

            if self._cursor.rowcount != 1:
                logging.critical("Unable to fetch ID of connection")
                return False

            connection_id = rows[0][0]
            logging.debug("Lookup connection ID : id = %d", connection_id)

        else:

            connection_id = self._cursor.lastrowid
            logging.debug("Created connection id = %d", connection_id)

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

            if vals[0] != "password":
                logging.debug("Created connection param: id = %d, name = %s, "
                              "value = %s",
                              connection_id, vals[0], vals[1])

        return connection_id

    def create_connection_group(self, name, parent=None):
        """Create a connection group at the root"""
        data = {'name': name, 'parent': parent}

        cmd = """
            SELECT connection_group_id FROM guacamole_connection_group
            WHERE
            connection_group_name = %(name)s
            AND
            type = 'ORGANIZATIONAL'
            AND
        """

        if parent is None:
            cmd += 'parent_id IS NULL'
        else:
            cmd += """
                parent_id = (
                    SELECT connection_group_id
                    FROM guacamole_connection_group
                    WHERE
                    connection_group_name = %(parent)s
                    AND
                    type = 'ORGANIZATIONAL'
                    AND
                    parent_id IS NULL
                )
                """

        try:
            self._cursor.execute(cmd, data)
        except mysql.connector.errors.DataError:
            logging.warning("DataError: Parent Group does not exist")
            return None

        rows = self._cursor.fetchall()
        if self._cursor.rowcount != 0:
            logging.debug("Connection group %s with parent %s exists",
                          name, parent)
            conn_id = rows[0][0]
            return conn_id

        if parent is None:
            cmd_parent = 'NULL'
        else:
            cmd_parent = """((
                SELECT connection_group_id
                FROM guacamole_connection_group cg
                WHERE
                cg.connection_group_name = %(parent)s
                AND
                cg.type = 'ORGANIZATIONAL'
                AND
                cg.parent_id IS NULL
            ))"""

        cmd = """
            INSERT INTO guacamole_connection_group
            (parent_id, type, connection_group_name)
            VALUES
            ({}, 'ORGANIZATIONAL', %(name)s)
        """.format(cmd_parent)

        self._cursor.execute(cmd, data)
        if self._cursor.rowcount != 1:
            logging.warning("Failed to insert connection group into database")
            return False

        logging.debug("Created connection group %s with parent %s",
                      name, parent)

        return self._cursor.lastrowid

    def set_connection_permission(self, connid, group):
        """Set Read Permissions on connection"""
        data = {
            'id': int(connid),
            'group': group,
            'permission': 'READ'
        }

        cmd = """
            INSERT INTO guacamole_connection_permission
            (connection_id, permission, entity_id)
            VALUES (
                %(id)s, %(permission)s, (
                    SELECT entity_id FROM guacamole_entity
                    WHERE
                    name = %(group)s AND
                    type = 'USER_GROUP'
                )
            )
            ON DUPLICATE KEY UPDATE
            connection_id = VALUES (connection_id)
        """
        self._cursor.execute(cmd, data)
        if self._cursor.rowcount != 1:
            logging.debug("Permission exists")

        logging.debug("Set %s permission on id %d for group %s",
                      data['permission'], data['id'], data['group'])

        return True

    def get_connection_permissions(self):
        """Get Connection permissions from DB"""
        cmd = """
            SELECT * FROM guacamole_connection_permission
            INNER JOIN guacamole_entity
            ON (guacamole_entity.entity_id =
                guacamole_connection_permission.entity_id)
            INNER JOIN guacamole_connection
            ON (guacamole_connection_permission.connection_id =
                guacamole_connection.connection_id)
            INNER JOIN guacamole_connection_group
            ON (guacamole_connection_group.connection_group_id =
                guacamole_connection_permission.entity_id)
        """

        return cmd

    def set_connection_group_permission(self, connid, group):
        """Set Read Permissions on connection groups"""
        data = {
            'id': int(connid),
            'group': group,
            'permission': 'READ'
        }

        cmd = """
            INSERT INTO guacamole_connection_group_permission
            (connection_group_id, permission, entity_id)
            VALUES (
                %(id)s, %(permission)s, (
                    SELECT entity_id FROM guacamole_entity
                    WHERE
                    name = %(group)s AND
                    type = 'USER_GROUP'
                )
            )
            ON DUPLICATE KEY UPDATE
            connection_group_id = VALUES (connection_group_id)
        """
        self._cursor.execute(cmd, data)
        if self._cursor.rowcount != 1:
            logging.debug("Permission exists")

        logging.debug("Set %s permission on connection group id %d for group %s",
                      data['permission'], data['id'], data['group'])

        return True
