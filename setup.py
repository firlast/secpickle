from setuptools import setup
from secpickle import __version__

with open('README.md', 'r') as file:
    readme = file.read()

setup(
    author='Firlast',
    author_email='firlastinc@gmail.com',
    name='secpickle',
    description="Use Python's Pickle Module Safely",
    long_description=readme,
    long_description_content_type='text/markdown',
    version=__version__,
    packages=['secpickle'],
    url='https://github.com/firlast/secpickle',
    keywords=['pickle', 'secure', 'safely', 'python']
)
