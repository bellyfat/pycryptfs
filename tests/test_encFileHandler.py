from unittest import TestCase
from pycryptfs.EncFileHandler import EncFileHandler
import hashlib


class TestEncFileHandler(TestCase):

    def test_read_enc_file(self):
        file_handler = EncFileHandler('master_key', 'keystore_path', 'resources', 'resources/test')
        file_handler.write_enc_file(file_name='sample_read.txt', data_key='data_key')
        file_handler.read_enc_file(file_name='sample_read.txt')
