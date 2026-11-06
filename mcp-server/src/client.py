import os
from pathlib import Path
from typing import Optional
from elasticsearch import AsyncElasticsearch
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
load_dotenv()


class ElasticClientManager:
    """Manages an async Elasticsearch client session."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        use_ssl: bool = False,
    ):
        self.host = host or os.getenv("ELASTIC_HOST", "localhost")
        self.port = port or int(os.getenv("ELASTIC_PORT", "9200"))
        self.username = username or os.getenv("ELASTIC_USER", "elastic")
        self.password = password or os.getenv("ELASTIC_PASSWORD", "ChangemeSecurePass2026!")
        self.api_key = api_key or os.getenv("ELASTIC_API_KEY")
        self.use_ssl = use_ssl or (os.getenv("ELASTIC_USE_SSL", "false").lower() == "true")

        scheme = "https" if self.use_ssl else "http"
        self.url = f"{scheme}://{self.host}:{self.port}"
        self._client: Optional[AsyncElasticsearch] = None

    def get_client(self) -> AsyncElasticsearch:
        if self._client is None:
            if self.api_key:
                self._client = AsyncElasticsearch(
                    hosts=[self.url],
                    api_key=self.api_key,
                    verify_certs=False if not self.use_ssl else True,
                )
            else:
                self._client = AsyncElasticsearch(
                    hosts=[self.url],
                    basic_auth=(self.username, self.password),
                    verify_certs=False if not self.use_ssl else True,
                )
        return self._client

    async def close(self):
        if self._client is not None:
            await self._client.close()
            self._client = None
