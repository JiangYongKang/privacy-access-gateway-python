"""本地运行入口：uv run uvicorn main:app。"""

from privacy_gateway.app import create_app

app = create_app()
