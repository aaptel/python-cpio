#!/usr/bin/env python
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor Boston, MA 02110-1301, USA

# Copyright 2011 Andrew Holmes <andrew.g.r.holmes@gmail.com>

"""
The :mod:`cpio` module provides a read-write implementation of the New ASCII
and New CRC (aka 'newc' and 'crc') cpio formats.  :class:`CpioArchive` and
:class:`CpioGzipArchive` act as containers for the archive's members which are
represented by :class:`CpioFile` objects.

All archive members are
buffered in memory to provide read-write file objects which inherit from
:class:`io.BytesIO`
"""

import io
import os
import os.path
import stat


__all__ = ['is_cpio', 'CpioArchive', 'CpioFile']


NEW_ASCII = '070701'
NEW_CRC = '070702'


def is_cpio(self, path):
    """Quickly check the magic number of a file or file object."""
    with io.open(path, 'rb') as fileobj:
        if fileobj.read(6) in (NEW_ASCII, NEW_CRC):
            return True
        else:
            return False


class Error(Exception):
    """Base class for cpio exceptions"""
    pass


class HeaderError(Error):
    """Raised when an unsupported magic number or invalid entry is read."""
    pass


class ChecksumError(HeaderError):
    """Raised when a checksum of an entry's data doesn't match its header."""
    pass


class CpioFile(io.BytesIO):
    """
    CpioFile is a simple subclass of :class:`io.BytesIO` which provides cpio
    header fields as attributes (some of which are dynamic)
    """

    def __init__(self, cpio):
        """CpioFile Constructor."""
        io.BytesIO.__init__(self)

        self._cpio = cpio
        """The CpioArchive object acting as a container for this instance."""
        self.c_mode = 0
        """Inode protection mode."""
        self.c_uid = 0
        """User id of the owner."""
        self.c_gid = 0
        """Group id of the owner."""
        self.c_mtime = 0
        """Time of last modification."""
        self.c_dev_maj = 0
        """Major number of the device the inode resides on."""
        self.c_dev_min = 0
        """Minor number of the device the inode resides on."""
        self.c_rdev_maj = 0
        """Major number of the device type."""
        self.c_rdev_min = 0
        """Minor number of the device type."""
        self.c_name = 'TRAILER!!!'
        """Pathname of the entry."""

    def _checksum(self):
        """
        If the entry is a regular file return a simple 32-bit unsigned sum of
        all the bytes in the file, otherwise return 0.
        """
        if stat.S_ISREG(self.c_mode):
            original_position = self.tell()
            self.seek(0)
            checksum = sum(ord(byte) for byte in self.read()) & 0xFFFFFFFF
            self.seek(original_position)
        else:
            checksum = 0

        return checksum

    @property
    def c_chksum(self):
        """
        Read only.  A 32-bit unsigned sum of all the bytes in the data field.
        This will always return 0 if :attr:`CpioArchive.checksum` is False or
        the entry is neither a regular file nor symbolic link.
        """
        if self._cpio.checksum:
            return self._checksum()
        else:
            return 0

    @property
    def c_filesize(self):
        """Read only.  Size of the file data in bytes."""
        original_position = self.tell()
        self.read()
        filesize = int(self.tell())
        self.seek(original_position)

        return filesize

    @property
    def c_magic(self):
        """
        Read only.  Magic number of the Cpio format.  The return value is
        based on :attr:`CpioArchive.checksum` attribute.
        """
        if self._cpio.checksum:
            return NEW_CRC
        else:
            return NEW_ASCII

    @property
    def c_namesize(self):
        """
        Read only.  The length of :attr:`c_name`, including trailing NUL byte.
        """
        return len(self.c_name) + 1

    @property
    def c_nlink(self):
        """
        Read only.  Number of links to the inode.  Returns 2 for directories,
        1 for any other type.
        """
        if stat.S_ISDIR(self.c_mode):
            return 2
        else:
            return 1


class CpioArchive(object):
    """
    CpioArchive is a simple file-like object which acts as a container of
    CpioFile objects, which in turn allow read and/or write access to the
    actual file data.
    """

    def __init__(self, path=None, mode='rb', fileobj=None, checksum=False):
        """Constructor for the CpioArchive class.

        Either *fileobj* or *path* must be given a non-trivial value.

        The new class instance is based on *fileobj*, which may be any binary
        file object which supports :meth:`readable()`, :meth:`writable()` and
        absolute seek().  If *fileobj* is None then *path* will be used to
        provide a file-object.

        The mode argument must be one of 'rb', 'r+b' or 'wb'.  The default is
        the mode of fileobj.

        The *checksum* argument must be either True or False and corresponds
        to the :attr:`CpioArchive.checksum` attribute.
        """

        self._entries = []
        self.checksum = checksum
        """
        Boolean determining whether the archive will be written as either New
        ASCII or New CRC.
        """
        if not path and not fileobj:
            raise ValueError('either fileobj or path must be given')

        # force binary mode
        if 'b' not in mode:
            mode += 'b'

        self.fileobj = fileobj or io.open(path, mode)

        # If the file object is readable, check the magic number
        if self.fileobj.readable():
            self._read_entries()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type is None:
            return self.close()

    def __iter__(self):
        return iter(self._entries)

    def _check_closed(self):
        """
        Raises a ValueError if the underlying file object has been closed.
        """
        if self.closed:
            raise ValueError('I/O operation on closed file.')

    def _check_readable(self):
        """
        Raises a IOError if the underlying file object is not open for reading
        """
        self._check_closed()

        if not self.fileobj.readable():
            import errno
            error_message = 'read operation on write-only CpioArchive object'

            raise IOError(errno.BADF, error_message)

    def _check_writable(self):
        """
        Raises a IOError if the underlying file object is not open for writing
        """
        self._check_closed()

        if not self.fileobj.writable():
            import errno
            error_message = 'write operation on read-only CpioArchive object'

            raise IOError(errno.BADF, error_message)

    def _read_entries(self):
        """."""
        archive_size = self.size
        tuple_buffer = []

        while self.fileobj.tell() < archive_size:
            entry = CpioFile(self)
            header = self.fileobj.read(110)

            #FIXME: arbitrary NUL padding, eg initramfs
            if header[0:6] == '\0\0\0\0\0\0':
                entry.close()
                return

            if header[0:6] not in (NEW_ASCII, NEW_CRC):
                raise HeaderError('unsupported format')

            try:
                c_magic = header[0:6]
                entry.c_ino = int(header[6:14], 16)
                entry.c_mode = int(header[14:22], 16)
                entry.c_uid = int(header[22:30], 16)
                entry.c_gid = int(header[30:38], 16)
                c_nlink = int(header[38:46], 16)
                entry.c_mtime = int(header[46:54], 16)
                c_filesize = int(header[54:62], 16)
                entry.c_dev_maj = int(header[62:70], 16)
                entry.c_dev_min = int(header[70:78], 16)
                entry.c_rdev_maj = int(header[78:86], 16)
                entry.c_rdev_min = int(header[86:94], 16)
                c_namesize = int(header[94:102], 16)
                c_chksum = int(header[102:110], 16)
            except IndexError:
                raise HeaderError('incomplete header')
            except ValueError:
                raise HeaderError('corrupted header')

            # Read filename, page align. Read file data, page align.
            entry.c_name = self.fileobj.read(c_namesize)[:-1]
            self.fileobj.read((4 - self.fileobj.tell() % 4) % 4)

            entry.write(self.fileobj.read(c_filesize))
            self.fileobj.read((4 - self.fileobj.tell() % 4) % 4)

            # Checksum the file if it bears the New CRC magic number
            if c_magic == NEW_CRC and entry._checksum() != c_chksum:
                raise ChecksumError(entry.c_name)

            # Strip dot files and trailer entries
            if entry.c_name not in ('.', '..', 'TRAILER!!!'):
                self._entries.append(entry)
            else:
                entry.close()

    def _write_entries(self):
        """."""
        self.fileobj.seek(0)

        # Sort the entries by length of pathname to ensure directories
        # are listed before any file that might be in them
        self._entries = sorted(self._entries, key=lambda e: e.c_name)

        # Return an 8-byte hex string from a decimal integer
        c_hex = lambda integer: hex(integer)[2:].rjust(8, '0')

        # Return a string of NUL bytes that makes *length* a multiple of 4
        c_pad = lambda length: '\0\0\0'[:(4 - length % 4) % 4]

        for entry in self._entries:
            entry.seek(0)

            self.fileobj.write(''.join([
                # Header
                entry.c_magic,
                c_hex(entry.c_ino),
                c_hex(entry.c_mode),
                c_hex(entry.c_uid),
                c_hex(entry.c_gid),
                c_hex(entry.c_nlink),
                c_hex(entry.c_mtime),
                c_hex(entry.c_filesize),
                c_hex(entry.c_dev_maj),
                c_hex(entry.c_dev_min),
                c_hex(entry.c_rdev_maj),
                c_hex(entry.c_rdev_min),
                c_hex(entry.c_namesize),
                c_hex(entry.c_chksum),
                entry.c_name, '\0',
                c_pad(110 + entry.c_namesize),

                # File data
                entry.read(),
                c_pad(entry.c_filesize)]))

    #FIXME
    def insert(self, path):
        """
        Read the file at *path* and append it to the archive.  Trying to add a
        dot-file ('.' or '..') or a file with a name that already exists will
        raise a :exc:`ValueError`.  Hardlinks are not supported and will be
        inserted as regular files.
        """
        # Raise an error if *path* is a dot-file or existing file
        if path in ('.', '..'):
            raise ValueError('dot files are not permitted')

        if path in self.namelist():
            raise ValueError('file %s already exists' % path)

        # Stat the file using lstat() (eg, don't follow symbolic links) and
        # set the header data
        st = os.lstat(path)
        entry = CpioFile(self)

        entry.c_ino = st.st_inode
        entry.c_mode = st.st_mode
        entry.c_uid = st.st_uid
        entry.c_gid = st.st_gid
        entry.c_mtime = st.st_mtime
        entry.c_dev_maj = os.major(st.st_dev)
        entry.c_dev_min = os.minor(st.st_dev)
        entry.c_rdev_maj = os.major(st.st_rdev)
        entry.c_rdev_min = os.minor(st.st_rdev)
        entry.c_name = path

        # Regular files and symbolic links are the only types with data
        if stat.S_ISREG(entry.c_mode):
            with io.open(path, 'rb') as fobject:
                entry.write(fobject.read())
                self._entries.append(entry)
        elif stat.S_IFLNK(entry.c_mode):
            # The target of a symbolic link is stored as file data
            entry.write(os.readlink(path))
            self._entries.append(entry)

    def close(self):
        """Flush and close this stream."""
        if self.fileobj is None:
            return

        self.flush()
        self.fileobj = None

    def closed(self):
        """True if the stream is closed."""
        return self.fileobj is None

    #FIXME: hardlinks
    def extract(self, name, path=None):
        """Extract an entry from the archive.

        The *name* argument should be the entry's pathname.

        The *path* argument is a path to a directory, defaulting to the
        current working directory, where the file will be extracted.  When
        extracting a single file
        """
        self._check_readable()

        # Retrieve the entry
        entry = self.get_entry(name)
        path = os.path.join(path or os.getcwd(), name)

        # Create a file on disk for the appropriate type
        if stat.S_ISDIR(entry.c_mode):
            mode = int(oct(entry.c_mode)[-4:], 8)
            os.mkdir(path, mode)
        elif stat.S_ISREG(entry.c_mode):
            with io.open(path, 'wb') as target:
                entry.seek(0)
                target.write(entry.read())
        # Symbolic link targets are stored as file data
        elif stat.S_ISLNK(entry.c_mode):
            entry.seek(0)
            os.symlink(entry.read(), path)
        # All other types will be created with os.mknod()
        else:
            device = os.makedev(entry.c_dev_major, entry.c_dev_minor)
            os.mknod(path, entry.c_mode, device)

    def fileno(self):
        """Invoke the underlying file object's fileno() method."""
        return self.fileobj.fileno()

    def flush(self):
        """Write all entries then flush the file-object"""

        if self.fileobj.writable() and self.fileobj.seekable():
            self._write_entries()

        self.fileobj.flush()

    def namelist(self):
        """Return a list of entry names."""
        return [entry.c_name for entry in self]

    @property
    def size(self):
        """Size of the archive in bytes."""
        original_position = self.fileobj.tell()
        self.fileobj.read()
        size = self.fileobj.tell()
        self.fileobj.seek(original_position)

        return size


def main():
    """."""
    with CpioArchive('cpio.test', 'rb') as cpio:
        print cpio.namelist()


if __name__ == "__main__":
    main()
