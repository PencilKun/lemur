"""
.. module: lemur.plugins.lemur_csr.plugin

An export plugin that exports CSR from a private key and certificate.
"""
import subprocess
import zipfile

from flask import current_app

from lemur.utils import mktempfile, mktemppath
from lemur.plugins.bases import ExportPlugin
from lemur.plugins import lemur_nginx as nginx

def run_process(command):
    """
    Runs a given command with pOpen and wraps some
    error handling around it.
    :param command:
    :return:
    """
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    current_app.logger.debug(command)
    stdout, stderr = p.communicate()

    if p.returncode != 0:
        current_app.logger.debug(" ".join(command))
        current_app.logger.error(stderr)
        raise Exception(stderr)


def create_pem_zip(cert, chain, pem_tmp, key):
    """
    Creates a csr from key and cert file.
    :param cert:
    :param chain:
    :param pem_tmp: path with file name
    :param key:
    """
    assert isinstance(cert, str)
    if chain:
        assert isinstance(chain, str)
    assert isinstance(key, str)

    with open(pem_tmp, 'wb') as of:
        with zipfile.ZipFile(of, mode='w') as zf:
            if chain:
                zf.writestr(pem_tmp+'-chain.pem', [cert.strip() + "\n", chain.strip() + "\n"])
            else:
                zf.writestr(pem_tmp+'.pem', cert)
            zf.writestr(pem_tmp+'.key', key)



class NginxExportPlugin(ExportPlugin):

    title = "Nginx(.pem)"
    slug = "export pem"
    description = "Exports a Nginx cert"
    version = nginx.VERSION

    author = "pencil"
    author_url = "https://github.com/pencilkun"

    def export(self, body, chain, key, options, **kwargs):
        """
        Creates pem from certificate

        :param key:
        :param chain:
        :param body:
        :param options:
        :param kwargs:
        """
        with mktemppath() as output_tmp:
            if not key:
                raise Exception("Private Key required by Nginx")

            create_pem_zip(body, chain, output_tmp, key)
            extension = "zip"

            with open(output_tmp, "rb") as f:
                raw = f.read()
        # passphrase is None
        return extension, None, raw
