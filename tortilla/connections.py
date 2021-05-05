import argparse
import re
import yaml

from N2SNUserTools import ADObjects
from .database import GuacamoleDatabase


def create_vnc_connection(group, conn_group, user_group,
                          password, view_only=None):
    if view_only is not None:
        postfix = ' ' + view_only;
        read_only = True
    else:
        postfix = ''
        read_only = False

    name = conn_group['name'] + postfix
    hostname = conn_group['hostname']

    id = db.create_connection_group(name, group)
    db.set_connection_group_permission(id, user_group)

    if 'displays' in conn_group:
        count = conn_group['displays']['count']
        prefix = conn_group['displays']['prefix']

        for n in range(1, count + 1):
            id = db.create_vnc_connection(
                '{} {}{}'.format(prefix, n, postfix),
                name, group,
                hostname,
                password,
                5900 + (n - 1),
                read_only
            )
            db.set_connection_permission(id, user_group)

    if 'aggregate' in conn_group:
        agg_name = conn_group['aggregate']['name']
        agg_name += postfix
        id = db.create_vnc_connection(
            agg_name,
            name, group,
            hostname,
            password,
            5909, read_only
        )
        db.set_connection_permission(id, user_group)


def setup_connections(config_file, filter=None):
    with open(config_file) as f:
        data = yaml.load(f, Loader=yaml.SafeLoader)

    db = GuacamoleDatabase(
        data['credentials']['database']['username'],
        password=data['credentials']['database']['password']
    )

    if filter is not None:
        re_filter = re.compile(filter)
    else:
        # Match anything
        re_filter = re.compile('^.*$')

    for conn in data['connections']:

        group = conn['name']
        if re_filter.match(group) is not None:
            user_ctrl_group = conn.get('user_ctrl_group')
            user_view_group = conn.get('user_view_group')

            db.create_user_group(user_ctrl_group)
            db.create_user_group(user_view_group)

            id = db.create_connection_group(group)
            db.set_connection_group_permission(id, user_ctrl_group)
            db.set_connection_group_permission(id, user_view_group)

            for conn_group in conn['workstations']:
                create_vnc_connection(
                    group, conn_group, user_ctrl_group,
                    password=data['credentials']['vnc']['password']
                )
                create_vnc_connection(
                    group, conn_group, user_view_group,
                    password=data['credentials']['vnc']['password'],
                    view_only='(View Only)'
                )


def setup_connections_cli():
    parser = argparse.ArgumentParser(
        prog=basename(sys.argv[0]),
        description=description
    )
