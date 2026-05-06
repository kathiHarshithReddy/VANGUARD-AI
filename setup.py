from setuptools import setup, find_packages

setup(
    name="vanguard",
    version="0.1.0",
    description="Project VANGUARD — Immutable Defense for the Post-Botnet Era",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "flask>=3.0.0",
        "numpy>=1.26.0",
        "scikit-learn>=1.4.0",
        "scipy>=1.12.0",
        "joblib>=1.3.0",
        "sqlparse>=0.5.0",
        "graphql-core>=3.2.3",
        "aiohttp>=3.9.0",
        "httpx>=0.27.0",
        "python-dotenv>=1.0.0",
        "pydantic>=2.6.0",
    ],
)
