from setuptools import setup

setup(
    name="whspider",
    version="0.1.0",
    packages=["modules"],
    py_modules=["cli"],
    install_requires=[
        "click",
        "rapidfuzz",
        # 웹 크롤링
        "requests",
        "beautifulsoup4",
        "playwright",
        "lxml",
        # RAG & LLM
        "sentence-transformers",
        "faiss-cpu",  # GPU 버전을 원하면 faiss-gpu로 변경
        "PyYAML",
        "numpy",
        "tqdm",
        # 기타
        "urllib3",
    ],
    entry_points={
        "console_scripts": [
            "whspider = cli:webspider",
        ],
    },
)
