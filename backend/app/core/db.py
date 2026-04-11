from sqlmodel import Session, SQLModel, create_engine

from backend.app.core.config import settings

_is_sqlite = settings.database_url.startswith("sqlite")

_engine_kwargs: dict = {"echo": False}
if _is_sqlite:
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    _engine_kwargs["pool_pre_ping"] = True

engine = create_engine(settings.database_url, **_engine_kwargs)


def get_session() -> Session:
    return Session(engine)


def init_db() -> None:
    if settings.app_create_tables:
        SQLModel.metadata.create_all(engine)

