from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="tarxemo-django-authz",
    version="0.2.1",
    author="TarXemo",
    description="A comprehensive, reusable Django authorization framework supporting RBAC and PBAC",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tarxemo/tarxemo-django-authz",
    packages=find_packages(exclude=["tests*", "bhumwi*", "management*"]),
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 3.2",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
    python_requires=">=3.8",
    install_requires=[
        "Django",
        "graphene-django",
        "tarxemo-django-graphene-utils",
    ],
    extras_require={
        "drf": ["djangorestframework"],
    },
)
