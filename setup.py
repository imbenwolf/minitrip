from setuptools import setup

setup(
        name='minitrip',
        version='0.1',
        description='Mini tripwire',
        py_modules=['minitrip'],
        entry_points = {
            'console_scripts': ['minitrip=minitrip:main']
        },
		install_requires = [ 'plyvel', 'click' ]
)