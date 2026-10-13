class BusinessError(Exception):
    """A rule violation with a human-readable explanation (shown to the user)."""
    def __init__(self, message: str, status: int = 409, reasons: list[str] | None = None):
        super().__init__(message)
        self.message, self.status, self.reasons = message, status, reasons or [message]
