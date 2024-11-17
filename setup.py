from setuptools import setup, find_packages
from setuptools_rust import Binding, RustExtension

setup(
    name="self_encryption",
    version="0.1.0",
    packages=find_packages(),
    rust_extensions=[RustExtension("self_encryption._self_encryption", binding=Binding.PyO3)],
    zip_safe=False,
    include_package_data=True,
    python_requires=">=3.7",
) 