"""codex32 / Bech32 encoding and usage errors."""


class CodexError(Exception):
    """Base class for all codex32 / Bech32 errors."""

    def __init__(self, extra: str | None = None) -> None:
        self.extra = extra
        super().__init__(extra)

    def __str__(self) -> str:
        return str(self.extra) if self.extra else ""
