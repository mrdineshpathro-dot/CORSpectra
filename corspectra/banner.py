from rich.console import Console
from rich.panel import Panel
from rich.text import Text

BANNER = r"""  _____ ___  ____  ____                  _             
 / ____/ _ \|  _ \/ ___| _ __   ___  ___| |_ _ __ __ _ 
| |   | | | | |_) \___ \| '_ \ / _ \/ __| __| '__/ _` |
| |___| |_| |  _ < ___) | |_) |  __/ (__| |_| | | (_| |
 \_____\___/|_| \_\____/| .__/ \___|\___|\__|_|  \__,_|
                        |_|"""


def show_banner(console: Console) -> None:
    text = Text(BANNER, style="bold cyan")
    text.append("\n        CORS Configuration Analyzer  v1.0.0", style="bold white")
    text.append("\n        Author: Mr Dinesh Pathro", style="bright_blue")
    text.append("\n        buymeacoffee.com/mrdineshpathro", style="yellow")
    console.print(Panel(text, border_style="cyan", padding=(1, 3)))
