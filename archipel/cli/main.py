import typer
from cli.commands import app as cli_app
from rich import print

app = typer.Typer(help="Logiciel de partage de fichiers P2P Archipel")

# On attache les commandes du dossier cli
app.add_typer(cli_app)

if __name__ == "__main__":
    print("[bold magenta]=== ARCHIPEL 14 v1.0 ===[/bold magenta]\n")
    app()