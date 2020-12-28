import time
from contextlib import contextmanager
from functools import update_wrapper
from pathlib import Path

import click


def info(msg, nl=True):
    click.echo("[*] {}".format(msg), nl=nl)


def error(msg, nl=True):
    click.echo("[error] {}".format(msg), nl=nl)


def header(msg):
    click.echo("#" * len(msg))
    click.echo(msg)
    click.echo("#" * len(msg))


@contextmanager
def timed_operation(msg, nl=False):
    start = time.time()
    info(msg, nl=nl)
    yield
    click.echo(" (done in {}s).".format(round(time.time() - start, 3)))


def ensure_config(f):
    @click.pass_context
    def decorator(__ctx, *args, **kwargs):
        from opencve.configuration import OPENCVE_CONFIG

        if not Path(OPENCVE_CONFIG).exists():
            error("Configuration not found (use the 'init' command)")
            __ctx.exit()
        return __ctx.invoke(f, *args, **kwargs)

    return update_wrapper(decorator, f)
