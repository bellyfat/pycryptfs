from . import BLOCK_SIZE


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64


class EncFileHandler:

    def __init__(self, master_key, keystore_path, unenc_mount, enc_mount):
        """

       Args:
           master_key (str): Master Key in its decrypted form.
           keystore_path (str): Path to json file containing all the secondary keys
           unenc_mount (str): Folder in the File System to store the unencrypted files.
           enc_mount (str): Folder in the File System to store the encrypted files.
       """
        self.__master_key = master_key
        self.__keystore_path = keystore_path
        self.__unenc_mount = unenc_mount
        self.__enc_mount = enc_mount

    def read_enc_file(self, file_name):
        """

        Args:
            file_name (str): Path of the file to be decrypted and read in the encrypted mount.

        Returns:
           str: Path to the unencrypted file.

        """
        # decryptor = Cipher(algorithms.AES(<data key>), modes.GCM(iv, tag), backend=default_backend()).decryptor()

        # if context:
        #    decryptor.authenticate_additional_data(context)

        # todo: figure out how to link files and secondary keys.
        unenc_file_path = os.path.join(self.__unenc_mount, '{}_{}'.format(file_name, 'fixed'))
        with open(os.path.join(self.__enc_mount, file_name), 'rb') as enc_file, open(unenc_file_path, 'wb') as unenc_file:
            chunk = enc_file.read(BLOCK_SIZE)
            while chunk:
                # file_contents = decryptor.update(encrypted_secret) + decryptor.finalize()
                unenc_file.write(chunk)
                chunk = enc_file.read(BLOCK_SIZE)

        return unenc_file_path

    def write_enc_file(self, file_name, data_key):
        """

        Args:
            file_name (str): Path of the file to be encrypted and written in the decrypted mount.
            data_key (str): Decrypted Data key to be used for encryption.

        Returns:
            None
        """
        enc_file_path = os.path.join(self.__enc_mount, file_name)
        with open(os.path.join(self.__unenc_mount, file_name), mode='rb') as unenc_file, open(enc_file_path, mode='wb') as enc_file:
            chunk = unenc_file.read(BLOCK_SIZE)
            while chunk:
                enc_file.write(chunk)
                chunk = unenc_file.read(BLOCK_SIZE)

        return enc_file_path
