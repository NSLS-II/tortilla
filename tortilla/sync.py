import sys
from os.path import expanduser
from configparser import ConfigParser
from N2SNUserTools import ADObjects
from random import randint
from .database import GuacamoleDatabase

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


config_files = ['/etc/tortilla.conf',
                expanduser('~/.config/tortilla.conf')]


def setup_logger():
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def read_config():
    config = ConfigParser()

    config.read(config_files)

    if 'database' not in config:
        raise RuntimeError("Bad config file format, "
                           "section 'database' missing")

    if 'group_sync' not in config:
        raise RuntimeError("Bad config file format, "
                           "section 'group_sync' missing")

    if 'ad_ldap' not in config:
        raise RuntimeError("Bad config file format, "
                           "section 'ad_ldap' missing")

    return config


def sync_groups(add=True, remove=True):

    setup_logger()

    logger.info("Starting")

    config = read_config()

    db = GuacamoleDatabase(
        config['database']['username'],
        config['database']['password']
    )

    ad_server = [s.strip() for s in config['ad_ldap']['server'].split(',')]
    logger.debug("AD Servers = %s", str(ad_server))
    ad_server = ad_server[randint(0, len(ad_server) - 1)]
    logger.debug("Using AD Server %s", ad_server)

    with ADObjects(ad_server,
                   user_search=config['ad_ldap']['user_search'],
                   group_search=config['ad_ldap']['group_search']) as ad:

        group_sync = config['group_sync']

        for group in group_sync:
            guac_group = group.upper()
            ad_group = [g.strip() for g in group_sync[group].split(',')]

            logger.info(
                "Processing guac_group = %s, AD group = %s",
                guac_group,
                ad_group
            )

            # Get list of unique UPNs from multiple groups
            members = [j for i in ad_group for j in ad.get_group_members(i)]
            members = list({v['userPrincipalName']:
                            v for v in members}.values())

            if add:
                logger.info("Processing addition")
                for member in members:
                    logger.info(
                        "Adding UPN '%s' to group '%s'",
                        member['userPrincipalName'],
                        guac_group
                    )
                    db.create_user(
                        member['userPrincipalName'],
                        member['displayName'],
                        member['mail'],
                        member['employeeID']
                    )
                    db.add_user_to_group(
                        member['userPrincipalName'],
                        guac_group
                    )

            if remove:
                logger.info("Processing removal")

                guac_group_members = db.get_group_members(guac_group)
                ad_group_members = [m['userPrincipalName'] for m in members]

                # Now use sets to see who is not in AD

                outside = list(set(guac_group_members) - set(ad_group_members))

                for upn in outside:
                    logger.info(
                        "Removing UPN '%s' from group '%s'",
                        upn, guac_group
                    )
                    db.remove_user_from_group(upn, guac_group)


def sync_groups_add():
    sync_groups(add=True, remove=False)


def sync_groups_remove():
    sync_groups(add=False, remove=True)
