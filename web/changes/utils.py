import logging
from difflib import HtmlDiff

logger = logging.getLogger(__name__)


class CustomHtmlHTML(HtmlDiff):
    def __init__(self, *args, **kwargs):
        self._table_template = """
        <table class="table table-diff table-condensed">
            <thead>
                <tr>
                    <th colspan="2">Old JSON</th>
                    <th colspan="2">New JSON</th>
                </tr>
            </thead>
            <tbody>%(data_rows)s</tbody>
        </table>"""
        super().__init__(*args, **kwargs)

    def _format_line(self, side, flag, linenum, text):
        text = text.replace("&", "&amp;").replace(">", "&gt;").replace("<", "&lt;")
        text = text.replace(" ", "&nbsp;").rstrip()
        return '<td class="diff_header">%s</td><td class="break">%s</td>' % (
            linenum,
            text,
        )
