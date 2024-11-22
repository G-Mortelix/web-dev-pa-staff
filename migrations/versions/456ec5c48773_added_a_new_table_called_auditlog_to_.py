"""added a new table called auditlog to track users behaviour

Revision ID: 456ec5c48773
Revises: 5af796c955d2
Create Date: 2024-11-22 15:49:10.177698

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = '456ec5c48773'
down_revision = '5af796c955d2'
branch_labels = None
depends_on = None


def upgrade():
    # Create the audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('log_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=255), nullable=False),
        sa.Column('target_file', sa.String(length=255), nullable=True),
        sa.Column('ip_address', sa.String(length=50), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('extra_data', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id']),
        sa.PrimaryKeyConstraint('log_id')
    )

    # Bind the connection and create an inspector
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)

    # Check for the existence of the foreign key constraint and drop if it exists
    folders_fks = [fk['name'] for fk in inspector.get_foreign_keys('folders')]
    if 'folders_ibfk_1' in folders_fks:
        op.drop_constraint('folders_ibfk_1', 'folders', type_='foreignkey')

    # Check for the existence of the foreign key on 'pdfs' and drop if it exists
    pdfs_fks = [fk['name'] for fk in inspector.get_foreign_keys('pdfs')]
    if 'folders_ibfk_1' in pdfs_fks:
        op.drop_constraint('folders_ibfk_1', 'pdfs', type_='foreignkey')

    # Check for the existence of the index on 'pdfs' and drop if it exists
    pdfs_indexes = [index['name'] for index in inspector.get_indexes('pdfs')]
    if 'folders_ibfk_1' in pdfs_indexes:
        op.drop_index('folders_ibfk_1', table_name='pdfs')


def downgrade():
    # Recreate the dropped foreign key and index for 'pdfs'
    op.create_foreign_key(
        'folders_ibfk_1', 'pdfs', 'folders', ['folder_id'], ['folder_id']
    )
    op.create_index('folders_ibfk_1', 'pdfs', ['folder_id'], unique=False)

    # Recreate the dropped foreign key and index for 'folders'
    op.create_foreign_key(
        'folders_ibfk_1', 'folders', 'departments', ['dept_id'], ['dept_id']
    )
    op.create_index('folders_ibfk_1', 'folders', ['dept_id'], unique=False)

    # Drop the audit_logs table
    op.drop_table('audit_logs')
