from setuptools import setup

setup(
    name='jupyterhub-xdmodauthenticator',
    version='0.1-dev',
    description='XDMoD Authenticator for JupyterHub',
    url='https://github.com/connersaeli/xdmodauthenticator',
    packages=['xdmodauthenticator'],
    install_requires=[
        'jupyterhub',
        'python-jose',
    ]
)
