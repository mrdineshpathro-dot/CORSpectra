from .csv_report import render_csv, write_csv
from .html_report import render_html, write_html
from .json_report import render_json, write_json
from .markdown_report import render_markdown, write_markdown

REPORTERS = {
    "json": (render_json, write_json),
    "csv": (render_csv, write_csv),
    "html": (render_html, write_html),
    "markdown": (render_markdown, write_markdown),
}
__all__ = ["REPORTERS"]
