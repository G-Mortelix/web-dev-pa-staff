"""Fix backref conflict in folders model

Revision ID: 9c096847c330
Revises: bff6b63a1979
Create Date: 2024-11-29 11:18:05.996478
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9c096847c330'
down_revision = 'bff6b63a1979'
branch_labels = None
depends_on = None


# 9c096847c330_fix_backref_conflict_in_folders_model.py

def upgrade():
    with op.batch_alter_table('folders', schema=None) as batch_op:
        # Check if constraint exists before trying to drop it
        # op.drop_constraint('folders_ibfk_1', 'folders', type_='foreignkey')
        # If the constraint does not exist, you can comment or remove the above line
        pass

def downgrade():
    with op.batch_alter_table('folders', schema=None) as batch_op:
        # You can also add the constraint back in the downgrade, if necessary.
        pass

    # ### end Alembic commands ###
