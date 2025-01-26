from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '58762dade8ec'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Creating the 'users' table
    op.create_table('users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('email', sa.String(length=100), nullable=False),
        sa.Column('_password_hash', sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('username')
    )
    
    # Creating the 'recipes' table
    op.create_table('recipes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=100), nullable=False),
        sa.Column('instructions', sa.Text(), nullable=False),
        sa.Column('minutes_to_complete', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_recipes_user_id_users')),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    # Dropping the 'recipes' table
    op.drop_table('recipes')
    
    # Dropping the 'users' table
    op.drop_table('users')
