"""Gradio app entrypoint for local and Spaces use."""

from __future__ import annotations

from apps.demo.gradio_app import build_demo


if __name__ == "__main__":
    build_demo().launch(share=True)
