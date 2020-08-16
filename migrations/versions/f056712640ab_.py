"""empty message

Revision ID: f056712640ab
Revises: c026a9a5204a
Create Date: 2020-08-16 17:03:59.824172

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'f056712640ab'
down_revision = 'c026a9a5204a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('fileupload')
    op.add_column('user', sa.Column('d_image', sa.String(length=100), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'd_image')
    op.create_table('fileupload',
    sa.Column('id', mysql.INTEGER(display_width=11), autoincrement=True, nullable=False),
    sa.Column('created_on', mysql.DATETIME(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_on', mysql.DATETIME(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('name', mysql.VARCHAR(length=32), nullable=False),
    sa.Column('file', sa.BLOB(), nullable=False),
    sa.Column('extension', mysql.VARCHAR(length=6), nullable=True),
    sa.Column('user_id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], name='fileupload_ibfk_1'),
    sa.PrimaryKeyConstraint('id'),
    mysql_default_charset='latin1',
    mysql_engine='InnoDB'
    )
    # ### end Alembic commands ###
