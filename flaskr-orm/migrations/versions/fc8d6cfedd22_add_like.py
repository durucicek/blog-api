"""add like

Revision ID: fc8d6cfedd22
Revises: dbcddad2337c
Create Date: 2024-07-25 11:40:43.113260

"""
from alembic import op # type: ignore
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fc8d6cfedd22'
down_revision = 'dbcddad2337c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('liked_posts',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('post_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['post_id'], ['post.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('user_id', 'post_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('liked_posts')
    # ### end Alembic commands ###
