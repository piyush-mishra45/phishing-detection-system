from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, scoped_session, sessionmaker


class Base(DeclarativeBase):
    pass


engine = None
Session = None


def init_engine(url: str):
    global engine, Session
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs["pool_recycle"] = 1800
    engine = create_engine(url, **kwargs)
    Session = scoped_session(sessionmaker(bind=engine, expire_on_commit=False))
    return engine


def init_db():
    from app.models import models  # noqa: F401  (register tables)
    Base.metadata.create_all(engine)


def db():
    return Session()
