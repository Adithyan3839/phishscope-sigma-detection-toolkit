from abc import ABC, abstractmethod

from .models import IOCType, TIResult


class TIProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        ...

    @abstractmethod
    def lookup(self, ioc_type: IOCType, ioc_value: str) -> TIResult:
        ...
