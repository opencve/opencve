"""Migrate the NVD format

Revision ID: 0bcd7a25924a
Revises: 1c7aecfc5f6e
Create Date: 2023-11-25 22:57:59.990718

"""

# revision identifiers, used by Alembic.
revision = "0bcd7a25924a"
down_revision = "1c7aecfc5f6e"

import arrow
from alembic import op
import sqlalchemy as sa

from opencve.models.cve import Cve
from opencve.models.metas import Meta


def upgrade():
    """This migration prepares the Meta table to handle the
    last CVE ID and its associated updatedAt date."""
    connection = op.get_bind()
    sessionmaker = sa.orm.sessionmaker()
    session = sessionmaker(bind=connection)

    # Get the last CVE
    cve = session.query(Cve).order_by(Cve.updated_at.desc()).first()
    if not cve:
        return

    # Create the metas data
    session.add(Meta(name="nvd_last_cve_id", value=cve.cve_id))
    session.add(Meta(name="nvd_last_cve_updated_at", value=cve.updated_at))
    session.commit()


def downgrade():
    connection = op.get_bind()
    sessionmaker = sa.orm.sessionmaker()
    session = sessionmaker(bind=connection)

    session.query(Meta).filter_by(name="nvd_last_cve_id").delete()
    session.query(Meta).filter_by(name="nvd_last_cve_updated_at").delete()
