import click
from ioc_topus.gui.app import open_gui

@click.group()
def cli():
    pass

@cli.command()
def gui():
    """Launch IOCTopus GUI."""
    open_gui()
