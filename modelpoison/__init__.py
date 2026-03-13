"""
modelpoison
~~~~~~~~~~~

ML attack vector generator and ModelAudit detection coverage reporter.

Quick start
-----------
Generate attack vectors::

    from modelpoison.cli import GENERATORS, cmd_generate
    import argparse
    args = argparse.Namespace(output="./out", only=["pickle", "pytorch"],
                              report=False, markdown=False)
    cmd_generate(args)

Build and render a coverage report::

    from modelpoison.report import build_report, render_markdown
    data = build_report("modelaudit.json", "attack_vectors_output")
    render_markdown(data)                   # stdout
    # or
    from modelpoison.report import write_report
    write_report(data, "coverage.md")       # file

CLI entry point::

    modelpoison generate --output ./vectors --only pickle pytorch
    modelpoison report   --sarif modelaudit.json --output coverage.md
"""

from modelpoison.report import (   # noqa: F401  (re-exported public API)
    build_report,
    render_markdown,
    render_text,
    write_report,
    ReportData,
    TypeRow,
    DISPLAY,
)
from modelpoison.cli import GENERATORS  # noqa: F401

__all__ = [
    "build_report",
    "render_markdown",
    "render_text",
    "write_report",
    "ReportData",
    "TypeRow",
    "DISPLAY",
    "GENERATORS",
]
