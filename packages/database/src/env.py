import os
from logging.config import fileConfig



config = context.config

# Force Alembic to use the DIRECT_DATABASE_URL from .env
section = config.get_section(config.config_ini_section)
section["sqlalchemy.url"] = os.getenv("DIRECT_DATABASE_URL")

fileConfig(config.config_file_name)
target_metadata = Base.metadata

def run_migrations_online():
    # Use NullPool for migrations to prevent hanging connections
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata,
            # Required for pgvector
            render_as_batch=True 
        )

        with context.begin_transaction():
            context.run_migrations()