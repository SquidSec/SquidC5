"""Out-of-band application security testing (Collaborator-style) interactions."""

from squidc5.oast.store import OastService, extract_token_from_host, extract_token_from_path

__all__ = ["OastService", "extract_token_from_host", "extract_token_from_path"]
