"""Synchronize null CVSS for existing CVEs

Revision ID: f81abceece3d
Revises: 41ad8e9163d4
Create Date: 2021-01-16 18:34:17.488053

"""

# revision identifiers, used by Alembic.
revision = "f81abceece3d"
down_revision = "41ad8e9163d4"

import datetime

from alembic import op
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base

from opencve.models.cve import Cve
from opencve.models.events import Event


def upgrade():
    """
    This migration is only useful for users who are upgrading
    from a previous version of OpenCVE.
    It fixes a bug when CVSS fields were not well filled.
    """
    connection = op.get_bind()
    sessionmaker = sa.orm.sessionmaker()
    session = sessionmaker(bind=connection)

    # Fetch the CVEs linked to CVSS events. Only the
    # events with an empty 'new' field are kept
    cves = [
        e.cve
        for e in session.query(Event).filter(Event.type == "cvss").all()
        if not e.details["new"]
    ]
    if not cves:
        return

    # Clean their cvss2 and cvss3 fields
    for cve in cves:
        cve.cvss2 = None
        cve.cvss3 = None

        # Small tip to keep the same updated_at attribute
        cve.updated_at = cve.updated_at + datetime.timedelta(seconds=1)
        session.commit()
        cve.updated_at = cve.updated_at + datetime.timedelta(seconds=-1)
        session.commit()


def downgrade():
    pass
