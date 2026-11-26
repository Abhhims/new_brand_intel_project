try:  # androguard logs every parse step through loguru; keep worker logs readable
    from loguru import logger as _loguru

    _loguru.disable("androguard")
except ImportError:  # pragma: no cover
    pass
