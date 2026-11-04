"""``python -m ai_triage`` starts the service with uvicorn (honours TRIAGE_HOST/TRIAGE_PORT)."""

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "ai_triage.main:create_app",
        factory=True,
        host=os.environ.get("TRIAGE_HOST", "0.0.0.0"),  # noqa: S104 - container service
        port=int(os.environ.get("TRIAGE_PORT", "8000")),
        server_header=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
