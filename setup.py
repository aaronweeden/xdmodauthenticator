from setuptools import setup

setup(
    name='jupyterhub-xdmodauthenticator',
    version='0.1-dev',
    description='XDMoD Authenticator for JupyterHub',
    url='https://github.com/aaronweeden/xdmodauthenticator',
    packages=['xdmodauthenticator'],
    install_requires=[
        'jupyterhub',
        'python-jose',
    ]
)
