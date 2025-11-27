"""Create OTP secrets table

Revision ID: 001_create_otp_secrets
Revises:
Create Date: 2024-06-10 00:00:00.000000

"""

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "001_create_otp_secrets"
down_revision = None
branch_labels = None
depends_on = None


def upgrade(op=None):
    # Create OTP secrets table
    op.create_table(
        "otp_secrets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("secret", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=True, default=False),
        sa.Column("backup_codes", sa.Text(), nullable=True),
        sa.Column("backup_code_attempts", sa.Integer(), nullable=True, default=0),
        sa.Column("backup_code_lockout_until", sa.Float(), nullable=True),
        sa.Column("otp_attempts", sa.Integer(), nullable=True, default=0),
        sa.Column("otp_lockout_until", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id"),
    )


def downgrade(op=None):
    op.drop_table("otp_secrets")
