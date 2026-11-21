"""add_user_id_to_scans

Revision ID: 002b4063f622
Revises: 002b4063f621
Create Date: 2026-11-21 18:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '002b4063f622'
down_revision: Union[str, Sequence[str], None] = '002b4063f621'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add user_id column with server default 'system-historical'
    op.add_column(
        'scans',
        sa.Column('user_id', sa.String(length=64), server_default='system-historical', nullable=False)
    )
    # 2. Create index for fast per-user multi-tenant query filtering
    op.create_index(
        op.f('ix_scans_user_id'),
        'scans',
        ['user_id'],
        unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_scans_user_id'), table_name='scans')
    op.drop_column('scans', 'user_id')
