# mark these as tasks, not real files.
.PHONY: format lint typecheck test security all

# Format code with Black
format:
	black .

# Lint code with Ruff
lint:
	ruff check .

# Type-check with mypy
typecheck:
	mypy .

# Run tests with coverage
test:
	pytest --cov

# Run security checks
security:
	bandit -r . 
	safety check

# Run everything
all: format lint typecheck test security
