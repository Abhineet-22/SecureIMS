import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


def make_engine(url: str) -> sa.Engine:
    is_sqlite = url.startswith("sqlite")
    engine = sa.create_engine(url, pool_pre_ping=True, **({"connect_args": {"check_same_thread": False}} if is_sqlite else {}))
    if is_sqlite:
        @event.listens_for(engine, "connect")
        def _on_connect(dbapi_conn, _):
            dbapi_conn.isolation_level = None  # we emit BEGIN ourselves
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=10000")
            cur.close()

        @event.listens_for(engine, "begin")
        def _on_begin(conn):
            # Writers are serialised: stock checks + audit-chain appends can never interleave.
            conn.exec_driver_sql("BEGIN IMMEDIATE")
    return engine


engine = make_engine(get_settings().database_url)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()  # uncommitted work is rolled back -> failed requests never change state
