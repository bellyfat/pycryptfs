import os
import errno
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fuse import FuseOSError, Operations, FUSE
BLOCK_SIZE = 4*1024


class EncFileHandler(Operations):

    def __init__(self, master_key, master_key_iv, root):
        """

       Args:
           master_key (bytes): Master Key in its decrypted form.
           master_key_iv (bytes): Master Key IV in its decrypted form.
       """

        # Keys to be used for encryption and decryption.
        self.__key = master_key
        self.__iv = master_key_iv

        # root to the filesystem
        self.__root = root

    def _full_path(self, partial):
        partial = partial.lstrip("/")
        path = os.path.join(self.__root, partial)
        return path

    # File methods
    def open(self, path, flags):
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)

    def read(self, path, length, offset, fh):
        """
        Read an encrypted file and decrypt its contents.

        Args:
            path (str): Path of the file to be decrypted and read in the encrypted mount.
            length (int): Number of bytes to be read from the file.
            offset (int): Position to write 'length' bytes to in the file handler.
            fh (File): Handler to a file like object

        Returns:
           bytes: Decrypted bytes read from the file.

        """
        decryption_suite = Cipher(algorithm=algorithms.AES(self.__key), mode=modes.GCM(self.__iv),
                                  backend=default_backend()).decryptor()

        os.lseek(fh, offset, os.SEEK_SET)
        decrypted_data = os.urandom(0)
        while length > BLOCK_SIZE:
            chunk = os.read(fh, BLOCK_SIZE)
            if not chunk:
                raise FuseOSError("Could not read from the file")

            length -= BLOCK_SIZE
            decrypted_data += decryption_suite.update(chunk)

        if length:
            chunk = os.read(fh, length)
            if not chunk:
                raise FuseOSError("Could not read from the file")

            decrypted_data += decryption_suite.update(chunk)

        return decrypted_data

    def write(self, path, buf, offset, fh):
        """
        Write an file while encrypting its contents.

        Args:
            path (str): Path of the unencrypted file.
            buf (): Buffer containing the data to be encrypted and written to the handler
            offset (int): Position to write 'length' bytes to in the file handler.
            fh (File): Handler to a file like object.

        Returns:
           int: Return the number of bytes written to the file

        """
        encryption_suite = Cipher(algorithm=algorithms.AES(self.__key), mode=modes.GCM(self.__iv),
                                  backend=default_backend()).encryptor()

        os.lseek(fh, offset, os.SEEK_SET)
        buf_len = len(buf)
        start = 0
        while buf_len > BLOCK_SIZE:
            chunk = buf[start:start+BLOCK_SIZE]
            if not chunk:
                raise FuseOSError("Could not read from the file")

            start += BLOCK_SIZE
            buf_len -= BLOCK_SIZE
            encrypted_data = encryption_suite.update(chunk)
            os.write(fh, encrypted_data)

        if buf_len:
            chunk = buf[start:]
            if not chunk:
                raise FuseOSError("Could not read from the file")

            encrypted_data = encryption_suite.update(chunk)
            os.write(fh, encrypted_data)

        return len(buf)

    # Filesystem methods

    def access(self, path, mode):
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                                                        'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size',
                                                        'st_uid'))

    def readdir(self, path, fh):
        full_path = self._full_path(path)

        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.__root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
                                                         'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files',
                                                         'f_flag',
                                                         'f_frsize', 'f_namemax'))

    def unlink(self, path):
        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        return os.symlink(target, self._full_path(name))

    def rename(self, old, new):
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        return os.link(self._full_path(name), self._full_path(target))

    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)


if __name__ == '__main__':
    with open('tests/resources/gold/key', 'rb') as key_file, open('tests/resources/gold/iv', 'rb') as iv_file:
        key = key_file.read()
        iv = iv_file.read()
        FUSE(EncFileHandler(key, iv, '/Users/vaddipar/Desktop/tests/resources/generated/unenc_mount'),
             '/Users/vaddipar/Desktop/tests/resources/generated/enc_mount', nothreads=True, foreground=True)