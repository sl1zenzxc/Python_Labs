import logging
from typing import Optional

import httpx
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, ValidationError

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class APIRecord(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    id: int


class Identification(APIRecord):
    title: Optional[str] = Field(None, alias='Title')
    category: Optional[str] = Field(None, alias='Category')
    attack_type: Optional[str] = Field(None, alias='Attack Type')


class AttackDescription(APIRecord):
    scenario_description: Optional[str] = Field(None, alias='Scenario Description')
    attack_steps: Optional[str] = Field(None, alias='Attack Steps')
    tools_used: Optional[str] = Field(None, alias='Tools Used')


class TargetVulnerability(APIRecord):
    target_type: Optional[str] = Field(None, alias='Target Type')
    vulnerability: Optional[str] = Field(None, alias='Vulnerability')
    mitre_technique: Optional[str] = Field(None, alias='MITRE Technique')


class ImpactProtection(APIRecord):
    impact: Optional[str] = Field(None, alias='Impact')
    detection_method: Optional[str] = Field(None, alias='Detection Method')
    solution: Optional[str] = Field(None, alias='Solution')


class Metadata(APIRecord):
    tags: Optional[str] = Field(None, alias='Tags')
    source: Optional[str] = Field(None, alias='Source')


class APIClient:
    def __init__(self, base_url: str, login: str, password: str, timeout: float = 15):
        self.http = httpx.Client(
            base_url=base_url.rstrip('/'),
            auth=httpx.BasicAuth(login, password),
            timeout=timeout,
            headers={'Accept': 'application/json'},
            trust_env=False,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.http.close()

    def _get_json(self, path: str) -> list[dict]:
        try:
            response = self.http.get(path)
            response.raise_for_status()
        except httpx.TimeoutException as error:
            raise RuntimeError(f'Превышено время ожидания: {path}') from error
        except httpx.HTTPStatusError as error:
            code = error.response.status_code
            messages = {401: 'Неверный логин или пароль',
                        403: 'Доступ запрещён',
                        404: 'Адрес API не найден'}
            message = messages.get(code, 'Ошибка сервера' if code >= 500 else 'Ошибка HTTP')
            raise RuntimeError(f'{message} ({code}): {path}') from error
        except httpx.RequestError as error:
            raise RuntimeError(f'Не удалось подключиться к {path}: {error}') from error

        try:
            result = response.json()
        except ValueError as error:
            raise RuntimeError(f'Некорректный JSON: {path}') from error

        if isinstance(result, dict):
            result = result.get('items')
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise RuntimeError(f'Неверный формат данных: {path}')
        logger.info('%s: получено %d записей', path, len(result))
        return result

    def _load(self, endpoint: str, model: type[APIRecord]) -> list[APIRecord]:
        try:
            return [model.model_validate(item) for item in self._get_json(endpoint)]
        except ValidationError as error:
            raise RuntimeError(f'Ошибка проверки данных {endpoint}: {error}') from error

    def fetch_identification(self) -> list[Identification]:
        return self._load('/api/identification', Identification)

    def fetch_attack_description(self) -> list[AttackDescription]:
        return self._load('/api/attack_description', AttackDescription)

    def fetch_target_vulnerability(self) -> list[TargetVulnerability]:
        return self._load('/api/target_vulnerability', TargetVulnerability)

    def fetch_impact_protection(self) -> list[ImpactProtection]:
        return self._load('/api/impact_protection', ImpactProtection)

    def fetch_metadata(self) -> list[Metadata]:
        return self._load('/api/metadata', Metadata)

    def fetch_all(self) -> pd.DataFrame:
        groups = [
            self.fetch_identification(),
            self.fetch_attack_description(),
            self.fetch_target_vulnerability(),
            self.fetch_impact_protection(),
            self.fetch_metadata(),
        ]
        tables = [pd.DataFrame([row.model_dump() for row in group]) for group in groups]
        if any('id' not in table.columns for table in tables):
            raise RuntimeError('Одна из групп не содержит данных с полем id')
        combined = tables[0]
        for table in tables[1:]:
            combined = pd.merge(combined, table, on='id', how='inner')
        return combined


def main():
    server = 'http://193.233.171.205:8000'
    try:
        with APIClient(server, 'student', 'student_pass') as client:
            data = client.fetch_all()
        filename = 'sql_injections_merged.csv'
        data.to_csv(filename, index=False, encoding='utf-8')
        logger.info('Готово: %s (%d строк, %d столбцов)', filename, *data.shape)
    except RuntimeError as error:
        logger.error('%s', error)
        raise SystemExit(1) from error


if __name__ == '__main__':
    main()
