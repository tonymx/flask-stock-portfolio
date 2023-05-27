"""add purchase date to stocks table

Revision ID: 5beedd8b20c8
Revises: e846859dd5ef
Create Date: 2023-05-19 18:37:34.539355

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5beedd8b20c8'
down_revision = 'e846859dd5ef'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('stocks', schema=None) as batch_op:
        batch_op.add_column(sa.Column('purchase_date', sa.DateTime(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('stocks', schema=None) as batch_op:
        batch_op.drop_column('purchase_date')

    # ### end Alembic commands ###
