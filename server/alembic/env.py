from logging.config import fileConfig
import os

from alembic import context
from sqlalchemy import engine_from_config, pool

from agentguard_server.config import get_settings
from agentguard_server.db.base import Base
from agentguard_server.models import anchoring, archive_resilience, integrity_segments, ledger, quorum, retention, telemetry  # noqa: F401

if context.config.config_file_name is not None:
    fileConfig(context.config.config_file_name)

config = context.config
config.set_main_option("sqlalchemy.url", os.getenv("DATABASE_URL", get_settings().database_url).replace("%", "%%"))
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(config.get_section(config.config_ini_section, {}), prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()


