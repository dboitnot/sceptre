#!/usr/bin/env python

from resolvers.vault import Vault

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Manage Sceptre Vault files')
    parser.add_argument('command', choices=['encrypt', 'decrypt', 'edit'])
    parser.add_argument('file')
    args = parser.parse_args()

    v = Vault()
    v.__getattribute__('cmd_%s' % args.command)(args.file)
