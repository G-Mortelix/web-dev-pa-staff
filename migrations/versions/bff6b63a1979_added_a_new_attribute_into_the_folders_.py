from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = 'bff6b63a1979'
down_revision = '456ec5c48773'
branch_labels = None
depends_on = None

def get_columns(table_name):
    """Helper function to get the column names of a table."""
    inspector = Inspector.from_engine(op.get_bind())
    columns = [column['name'] for column in inspector.get_columns(table_name)]
    return columns

# This is the migration script where you modify the constraint drop operation
def upgrade():
    with op.batch_alter_table('folders') as batch_op:
        batch_op.drop_constraint('folders_ibfk_1', type_='foreignkey')  # Correct constraint name
        batch_op.drop_constraint('folders_ibfk_2', type_='foreignkey')
        # Continue with other operations like adding columns or changing data types

def downgrade():
    with op.batch_alter_table('folders') as batch_op:
        batch_op.create_foreign_key('folders_ibfk_1', 'departments', ['dept_id'], ['dept_id'])
        batch_op.create_foreign_key('folders_ibfk_2', 'folders', ['parent_folder_id'], ['folder_id'])
    
    # ### end Alembic commands ###

