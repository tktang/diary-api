"""empty message

Revision ID: 4225ae69ee58
Revises: 3de2b212cff7
Create Date: 2020-08-19 14:54:21.980713

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '4225ae69ee58'
down_revision = '3de2b212cff7'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('display_image', sa.String(length=100), nullable=True))
    op.drop_column('user', 'confirmed')
    op.drop_column('user', 'confirmed_on')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('confirmed_on', mysql.DATETIME(), nullable=True))
    op.add_column('user', sa.Column('confirmed', mysql.TINYINT(display_width=1), autoincrement=False, nullable=True))
    op.drop_column('user', 'display_image')
    # ### end Alembic commands ###
