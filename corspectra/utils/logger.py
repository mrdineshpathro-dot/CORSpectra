import logging

from rich.logging import RichHandler


def configure_logging(
    verbose: bool = False, debug: bool = False, quiet: bool = False
) -> logging.Logger:
    level = (
        logging.ERROR
        if quiet
        else logging.DEBUG
        if debug
        else logging.INFO
        if verbose
        else logging.WARNING
    )
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=debug, show_path=debug)],
        force=True,
    )
    return logging.getLogger("corspectra")
