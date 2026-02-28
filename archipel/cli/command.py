import typer
from utils.logger import log_info, log_success

app = typer.Typer()

@app.command()
def start(port: int = typer.Option(7777, help="Port TCP d'écoute")):
    """Démarre le nœud Archipel 14."""
    log_info("Démarrage du système...")
    # Simulation de l'appel aux autres modules (Sprints suivants)
    log_info(f"Serveur TCP en attente sur le port {port}")
    log_success("Nœud Archipel 14 prêt et opérationnel !")