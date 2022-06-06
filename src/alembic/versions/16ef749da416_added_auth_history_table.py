"""Added auth_history table

Revision ID: 16ef749da416
Revises: 0be611504f88
Create Date: 2022-05-29 23:26:05.915272

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '16ef749da416'
down_revision = '0be611504f88'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('auth_history',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
    sa.Column('ip_address', sa.String(length=50), nullable=True),
    sa.Column('user_agent', sa.Text(), nullable=False),
    sa.Column('platform', sa.Text(), nullable=True),
    sa.Column('browser', sa.Text(), nullable=True),
    sa.Column('date', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id'),
    postgresql_partition_by="LIST (platform)",
    )
    op.create_unique_constraint(None, 'film', ['id'])
    op.create_unique_constraint(None, 'roles', ['id'])
    op.create_unique_constraint(None, 'users', ['id'])
    op.create_unique_constraint(None, "auth_history", ["id", "platform"])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='unique')
    op.drop_constraint(None, 'roles', type_='unique')
    op.drop_constraint(None, 'film', type_='unique')
    op.drop_constraint(None, "auth_history", type_="unique")
    op.drop_table('auth_history')
    # ### end Alembic commands ###
