"""Abstract base class for all tool adapters."""

from abc import ABC, abstractmethod

from guardbench.schemas import Result, TestCase


class ToolAdapter(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this tool adapter."""

    @abstractmethod
    def evaluate(self, test_case: TestCase) -> Result:
        """Run a single test case through the tool and return a Result."""

    def setup(self) -> None:
        """Optional setup hook. Override in subclasses that need initialization."""

    def evaluate_with_retries(self, test_case: TestCase, n_runs: int = 1) -> list[Result]:
        """Call evaluate *n_runs* times and return all results."""
        return [self.evaluate(test_case) for _ in range(n_runs)]
