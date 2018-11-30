from unittest import TestCase
from pycryptfs.EncFileHandler import EncFileHandler
import os
import hashlib
import shutil


class TestEncFileHandler(TestCase):

    def __get_md5_hash(self, file_path):
        with open(file_path, 'r') as src_path:
            return hashlib.md5(src_path.read().encode('ascii')).hexdigest()

    def test_read_enc_file(self):

        with open('resources/gold/key', 'rb') as key_file, open('resources/gold/key', 'rb') as iv_file:
            key = key_file.read()
            iv = iv_file.read()


        file_handler = EncFileHandler(master_key=key, master_key_iv=iv, keystore_path='',
                                      unenc_mount='resources/generated/unenc_mount',
                                      enc_mount='resources/generated/enc_mount')

        # copying the gold file to the unencrypted mount.
        os.makedirs('resources/generated/unenc_mount')
        os.makedirs('resources/generated/enc_mount')
        shutil.copy('resources/gold/sample_read.txt', 'resources/generated/unenc_mount')

        enc_file_path = file_handler.write(file_name='sample_read.txt')
        file_handler.read(path=enc_file_path)

        assert self.__get_md5_hash('resources/generated/unenc_mount/sample_read.txt') \
               == self.__get_md5_hash('resources/gold/sample_read.txt')

        shutil.rmtree('resources/generated/unenc_mount')
        shutil.rmtree('resources/generated/enc_mount')
