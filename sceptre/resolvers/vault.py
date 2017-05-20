from sceptre.resolvers import Resolver
import simplecrypt
import os
import os.path
import base64
import tempfile
import subprocess
import yaml
import textwrap


class Vault(object):
    def __init__(self):
        self.header = ':SCEPTRE-VAULT:1'

        # Load key from environment variable
        self.key = os.environ.get('SCEPTRE_VAULT_PASSWORD')
        if self.key is None:
            raise KeyError('SCEPTRE_VAULT_PASSWORD not set in environment')

    def read_encrypted_file(self, path):
        with open(path, 'r') as fp:
            header, filename, cypher_text = fp.read().split('\n', 2)
        if header != self.header:
            raise ValueError('Unrecognized file header. Was this encrypted with sceptre-vault?')
        filename = filename[1:]
        cypher_text = base64.b64decode(cypher_text)
        return simplecrypt.decrypt(self.key, cypher_text), filename

    def write_encrypted_file(self, path, plain_text):
        cypher_text = simplecrypt.encrypt(self.key, plain_text)
        cypher_text = base64.b64encode(cypher_text)
        cypher_text = textwrap.fill(cypher_text)
        path_header = ':' + os.path.basename(path)
        with open(path, 'w') as fp:
            print >> fp, '\n'.join([self.header, path_header, cypher_text])

    def cmd_edit(self, path):
        editor = os.environ.get('EDITOR')
        if editor is None:
            raise KeyError('EDITOR not set in environment')
        plain_text, filename = self.read_encrypted_file(path)
        fd, temp_path = tempfile.mkstemp(filename)
        try:
            with os.fdopen(fd, 'w') as fp:
                fp.write(plain_text)

            # Launch the user's editor
            res = subprocess.call("%s %s" % (editor, temp_path), shell=True)
            if res != 0:
                print "Editor exited with code %d, aborting." % res
                return

            # Looks like a good edit. Save the result.
            with open(temp_path, 'r') as fp:
                plain_text = fp.read()
            self.write_encrypted_file(path, plain_text)
        finally:
            os.remove(temp_path)

    def cmd_encrypt(self, path):
        with open(path, 'r') as fp:
            plain_text = fp.read()
        self.write_encrypted_file(path, plain_text)

    def cmd_decrypt(self, path):
        plain_text, _ = self.read_encrypted_file(path)
        with open(path, 'w') as fp:
            print >> fp, plain_text,


class VaultParameter(Resolver):
    def __init__(self, *args, **kwargs):
        super(VaultParameter, self).__init__(*args, **kwargs)

    def resolve(self):
        secrets_file = os.path.join(self.stack_config.sceptre_dir, 'config', 'secrets.yaml')
        plain_text, _ = Vault().read_encrypted_file(secrets_file)
        data = yaml.load(plain_text)
        stack_name = self.stack_config.name

        data_keys = self.stack_config.environment_path.split('/') + [stack_name, self.argument]
        data_path = '.'.join(data_keys)
        for k in data_keys:
            if k not in data:
                raise KeyError("key '%s' not found in secrets file %s" % (data_path, secrets_file))
            data = data[k]

        return data
