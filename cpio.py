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
The CPIO file format is a common UNIX archive standard which collects file
system objects into a single stream of bytes.  This module provides tools to
create, read, write (unfinished), and list CPIO archives.

This module currently supports the old ASCII (odc), New ASCII (newc) and New
CRC (crc).
"""

import io
import os
import os.path
import stat
import struct


__all__ = ['is_cpioarchive', 'CpioArchive', 'CpioEntry']


MAGIC_BIN = 070707
MAGIC_OLD = '070707'
MAGIC_NEW = '070701'
MAGIC_CRC = '070702'

_STRUCT_NEW = '6s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s'
_STRUCT_OLD = '6s 6s 6s 6s 6s 6s 6s 6s 11s 6s 11s'
_STRUCT_BIN = 'H H H H H H H H H H H H H'


def is_cpioarchive(self, path):
    """Quickly check the magic number of a file."""
    with io.open(path, 'rb') as fileobj:
        magic = fileobj.read(6)

    if magic in (MAGIC_NEW, MAGIC_CRC):
        return True
    else:
        return False


def checksum32(bytes):
    """Return a 32-bit unsigned sum of *bytes*."""
    return sum(ord(byte) for byte in bytes) & 0xFFFFFFFF


def hex8(integer):
    """Return an 8-byte hex string from *integer*."""
    return hex(integer)[2:].rjust(8, '0')


def u16(n):
    """."""
    return chr(n / 256) + chr(n % 256)


def u32(integer):
    """."""
    return ''.join([
        chr(integer / 256 / 256 / 256),
        chr(integer / 256 / 256),
        chr(integer / 256),
        chr(integer % 256)])


class Error(Exception):
    """Base class for cpio exceptions"""
    pass


class HeaderError(Error):
    """Raised when an unsupported magic number or invalid entry is read."""
    pass


class ChecksumError(HeaderError):
    """Raised when a checksum of an entry's data doesn't match its header."""
    pass


class CpioEntry(object):
    """."""
    __slots__ = [
        '_cpio',
        '_position',
        '_offset',
        '_size',
        'fileobj',
        'c_magic',
        'c_ino',
        'c_mode',
        'c_uid',
        'c_gid',
        'c_nlink',
        'c_mtime',
        'c_filesize',
        'c_dev',
        'c_rdev',
        'c_namesize',
        'c_check',
        'name']

    def __init__(self, cpio, path=None):
        """."""
        self._cpio = cpio
        self.fileobj = cpio.fileobj
        self._offset = 0
        self._size = 0
        self._position = 0

        self.c_ino = 0
        """Inode number on disk."""
        self.c_mode = 0
        """Inode protection mode."""
        self.c_uid = 0
        """User id of the owner."""
        self.c_gid = 0
        """Group id of the owner."""
        self.c_nlink = 0
        """Number of links to the inode."""
        self.c_mtime = 0
        """Time of last modification."""
        self.c_filesize = 0
        """Size of the file data in bytes.."""
        self.c_dev = 0
        """Number of the device the inode resides on."""
        self.c_rdev = 0
        """Number of the device type."""
        self.name = 'TRAILER!!!'
        """Pathname of the entry."""

    @property
    def c_magic(self):
        """Magic number of the cpio format."""
        return self._cpio.format

    @property
    def c_namesize(self):
        """Name size in bytes, including the trailing NUL byte."""
        return len(self.name) + 1

    #FIXME: test
    def read(self, n=-1):
        """FIXME"""
        # seek to current object position, if not already there
        if self.fileobj.tell() != self._offset + self._position:
            self.fileobj.seek(self._offset + self._position)

        # return '' if at EOF for this object
        if self.fileobj.tell() == self._offset + self._size:
            return ''

        #
        if n < 0 or n >= (self.filesize - self._position):
            data = self.fileobj.read(self.filesize - self._position)
        else:
            data = self.fileobj.read(n)

        self._position += len(data)

        return data

    def seek(self, offset, whence=0):
        """
        Change the stream position to the given byte *offset*.  *offset* is
        interpreted relative to the position indicated by *whence*. Values for
        *whence* are synonymous to those in the :mod:`io` module.
        """
        if whence == 0:
            self._position = offset
        elif whence == 1:
            self._position += offset
        elif whence == 2:
            self._position -= offset

        self._position = min(max(0, self._position), self.c_filesize)

    def tell(self):
        """Return the current stream position."""
        return self._position

    def _ino(self):
        return (self.c_ino, self.c_devmajor, self.c_devminor)

    def _ishardlink(self):
        if not stat.S_ISDIR(self.c_mode) and self.c_nlink > 1:
            return True


class CpioArchive(object):
    """
    CpioArchive is a simple file-like object which acts as a container of
    CpioEntry objects, which in turn allow read and/or write access to the
    actual file data.
    """

    def __init__(self, path=None, mode=None, fileobj=None, format=MAGIC_NEW):
        """Constructor for the CpioArchive class.

        Either *fileobj* or *path* must be given a non-trivial value.

        The new class instance is based on *fileobj*, which may be any binary
        file object which supports read(), write() and seek() methods.  If
        *fileobj* is None then *path* will be used to provide a file-object.

        The *mode* argument must be either 'rb' or 'wb'.  The default is 'rb'
        either if *path* is given or if *fileobj* is read-write.

        The *checksum* argument'
        """
        if not path and not fileobj:
            raise ValueError('either fileobj or path must be given')

        if mode not in('rb', 'wb'):
            raise ValueError('mode must be either "rb" or "wb".')

        self._entries = []

        self.fileobj = fileobj or io.open(path, mode or 'rb')
        self.format = self._read_magic() or format
        """."""

        # If the file object is readable and a known format, read it
        if self.fileobj.readable():
            hardlinks = []

            entry = self._read()

            while entry.name != 'TRAILER!!!':
                self._entries.append(entry)
                entry = self._read()

                if entry._ishardlink() and entry.c_filesize > 0:
                    hardlinks.append(entry)

            #FIXME ### Hardlinks
            for link in hardlinks:
                for entry in self:
                    if entry._ino() == link._ino() and entry.c_filesize > 0:
                        link._offset = entry._offset
                        link.c_filesize = entry.c_filesize
                        link.c_nlink = 1
                        break

    def __enter__(self):
        return self

    def __exit__(self, extype, exvalue, extraceback):
        if extype is None:
            return self.close()

    def __iter__(self):
        return iter(self._entries)

    def __repr__(self):
        s = repr(self.fileobj)
        return '<cpio ' + s[1:-1] + ' ' + hex(id(self)) + '>'

    def _read_magic(self):
        """."""
        if self.fileobj.readable():
            magic = self.fileobj.read(6)
            self.fileobj.seek(0)

            if magic in (MAGIC_NEW, MAGIC_CRC, MAGIC_OLD):
                return magic
            elif struct.unpack('H', magic[:2])[0] == MAGIC_BIN:
                return MAGIC_BIN
            elif magic == '':
                return False

            raise HeaderError('unknown format')

    def _read(self):
        """."""
        header = self.struct.unpack(self.fileobj.read(self.struct.size))
        entry = CpioEntry(self)

        if self.format in (MAGIC_NEW, MAGIC_CRC):
            # Reading the header, some values will be dynamic (eg c_namesize)
            #c_magic = header[0]
            entry.c_ino = int(header[1], 16)
            entry.c_mode = int(header[2], 16)
            entry.c_uid = int(header[3], 16)
            entry.c_gid = int(header[4], 16)
            entry.c_nlink = int(header[5], 16)
            entry.c_mtime = int(header[6], 16)
            entry.c_filesize = int(header[7], 16)
            entry.c_dev = os.makedev(int(header[8], 16), int(header[9], 16))
            entry.c_rdev = os.makedev(int(header[10], 16), int(header[11], 16))
            c_namesize = int(header[12], 16)
            entry.c_check = int(header[13], 16)

            # Read the name, exclude trailing NUL byte and header padding
            hpad = (4 - (self.struct.size + c_namesize) % 4) % 4
            entry.name = self.fileobj.read(c_namesize + hpad)[:-hpad + -1]
            entry._offset = self.fileobj.tell()

            # Reading the file data. Checksum if necessary.
            dpad = (4 - entry.c_filesize % 4) % 4

            if self.format == MAGIC_CRC and stat.S_ISREG(entry.c_mode):
                data = self.fileobj.read(entry.c_filesize + dpad)[:-dpad]

                if checksum32(data) != entry.c_check:
                    raise ChecksumError(entry.name)
            else:
                self.fileobj.read(entry.c_filesize + dpad)
        elif self.format == MAGIC_OLD:
            #c_magic = header[0]
            entry.c_dev = int(header[1], 8)
            entry.c_ino = int(header[2], 8)
            entry.c_mode = int(header[3], 8)
            entry.c_uid = int(header[4], 8)
            entry.c_gid = int(header[5], 8)
            entry.c_nlink = int(header[6], 8)
            entry.c_rdev = int(header[7], 8)
            entry.c_mtime = int(header[8], 8)
            c_namesize = int(header[9], 8)
            entry.c_filesize = int(header[10], 8)

            entry.name = self.fileobj.read(c_namesize)[:-1]
            entry._offset = self.fileobj.tell()
            self.fileobj.read(entry.c_filesize)
        #FIXME
        elif self.format == MAGIC_BIN:
            #c_magic = header[0]
            entry.c_dev = header[1]
            entry.c_ino = header[2]
            entry.c_mode = header[3]
            entry.c_uid = header[4]
            entry.c_gid = header[5]
            entry.c_nlink = header[6]
            entry.c_rdev = header[7]
            entry.c_mtime = header[8]
            c_namesize = header[9]
            entry.c_filesize = header[10]

            hpad = (2 - (self.struct.size + c_namesize) % 2) % 2
            entry.name = self.fileobj.read(c_namesize + hpad)[:-hpad + -1]
            entry._offset = self.fileobj.tell()

            dpad = (2 - entry.c_filesize % 2) % 2
            self.fileobj.read(entry.c_filesize + dpad)

        entry._size = entry.c_filesize

        return entry

    #FIXME
    def _write(self, entry, data=None):
        """."""

        if data is not None:
            if stat.S_ISREG(entry.c_mode) or stat.S_ISLNK(entry.c_mode):
                pass
            if self.checksum and stat.S_ISREG(entry.c_mode):
                entry.c_check = checksum32(data)

        if self.format in (MAGIC_NEW, MAGIC_CRC):
            hpad = (4 - (self.struct.size + entry.c_namesize) % 4) % 4
            self.fileobj.write(
                self.struct.pack(
                    entry.c_magic,
                    hex8(entry.c_ino),
                    hex8(entry.c_mode),
                    hex8(entry.c_uid),
                    hex8(entry.c_gid),
                    hex8(entry.c_nlink),
                    hex8(entry.c_mtime),
                    hex8(entry.c_filesize),
                    hex8(os.major(entry.c_dev)),
                    hex8(os.minor(entry.c_dev)),
                    hex8(os.major(entry.c_rdev)),
                    hex8(os.minor(entry.c_rdev)),
                    hex8(entry.c_namesize),
                    hex8(entry.c_check)))

            dpad = (4 - entry.c_filesize % 4) % 4
            self.fileobj.write(
                entry.name, '\0',
                ''.ljust(hpad, '\0'),
                data,
                ''.ljust(dpad, '\0'))
        elif self.format == MAGIC_OLD:
            self.fileobj.write(
                self.struct.pack(
                    entry.c_magic,
                    oct(entry.c_dev).rjust(6, '0'),
                    oct(entry.c_ino).rjust(6, '0'),
                    oct(entry.c_mode).rjust(6, '0'),
                    oct(entry.c_uid).rjust(6, '0'),
                    oct(entry.c_gid).rjust(6, '0'),
                    oct(entry.c_nlink).rjust(6, '0'),
                    oct(entry.c_rdev).rjust(6, '0'),
                    oct(entry.c_mtime).rjust(11, '0'),
                    oct(entry.c_namesize).rjust(6, '0'),
                    oct(entry.c_filesize).rjust(11, '0')))

            self.fileobj.write(entry.name + '\0' + data)
        elif self.format == MAGIC_BIN:
            self.fileobj.write(
                self.struct.pack(
                    entry.c_magic,
                    entry.c_dev,
                    entry.c_ino,
                    entry.c_mode,
                    entry.c_uid,
                    entry.c_gid,
                    entry.c_nlink,
                    entry.c_rdev,
                    entry.c_mtime,
                    entry.c_namesize,
                    entry.c_filesize))

            hpad = (2 - (self.struct.size + entry.c_namesize) % 2) % 2
            dpad = (2 - entry.c_filesize % 2) % 2
            self.fileobj.write(entry.name + '\0' + ''.rjust(hpad, '\0') + data + ''.rjust(dpad, '\0'))

    def close(self):
        """Flush and close this stream."""
        if self.fileobj is None:
            return

        self.flush()
        self.fileobj = None

    def closed(self):
        """True if the stream is closed."""
        return self.fileobj is None

    #FIXME: everything
    def extract(self, name, path=None):
        """Extract an entry from the archive.

        The *name* argument should be the entry's pathname.

        The *path* argument is a path to a directory, defaulting to the
        current working directory, where the file will be extracted.  When
        extracting a single file
        """
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
        elif stat.S_ISLNK(entry.mode):
            entry.seek(0)
            os.symlink(entry.read(), path)
        # All other types will be created with os.mknod() FIXME: formats
        else:
            device = entry.c_dev
            os.mknod(path, entry.c_mode, device)

    def fileno(self):
        """Invoke the underlying file object's fileno() method."""
        return self.fileobj.fileno()

    def flush(self):
        """Write a trailer entry, if writable(), and flush the file-object"""
        if self.fileobj.writable():
            self._write_entry(CpioEntry(self))

        self.fileobj.flush()

    @property
    def format(self):
        """."""
        return self._format

    @format.setter
    def format(self, value):
        """."""
        if value in (MAGIC_NEW, MAGIC_CRC):
            self.struct = struct.Struct(_STRUCT_NEW)
        elif value == MAGIC_OLD:
            self.struct = struct.Struct(_STRUCT_OLD)
        elif value == MAGIC_BIN:
            raise Error('old binary format not yet supported')
            self.struct = struct.Struct(_STRUCT_BIN)
        else:
            raise Error('unsupported format')

        self._format = value


    def namelist(self):
        """Return a list of entry names."""
        return [entry.name for entry in self]

    #FIXME
    def readable(self):
        """Return True if the stream can be read from."""
        return self.mode is 'rb'

    #FIXME
    def seekable(self):
        """Return True if the stream supports random access."""
        return self.fileobj.seekable()

    #FIXME
    def write(self, path, header=None):
        """
        Write the file *path* to the archive. :meth:`os.lstat()` will be
        called to populate the cpio header fields.

        If given, *header* should be a dictionary object or an iterable of
        key/value pairs to be used to amend the header fields.
        """

        st = os.lstat(path)
        entry = CpioEntry(self)
        entry.c_ino = st.st_ino
        entry.c_mode = st.st_mode
        entry.c_uid = st.st_uid
        entry.c_gid = st.st_gid
        entry.c_nlink = st.st_nlink
        entry.c_mtime = st.st_mtime
        entry.c_filesize = st.st_size
        entry.c_dev = st.st_dev

        # st_rdev may not be available on non-Linux systems
        try:
            entry.c_rdev = st.st_rdev
        except AttributeError:
            pass

        entry.name = path

        # write the data; regular files and symbolic links only
        #if stat.S_ISREG(entry.c_mode):
        #    with io.open(path, 'rb') as fobject:
        #        data = fobject.read()
        #elif stat.S_IFLNK(entry.mode):
        #    # The target of a symbolic link is stored as file data
        #    data = os.readlink(path)


        ########### check header

        # duplcate named entries are not allowed
        if entry.name in self.namelist():
            raise ValueError('file %s already exists' % entry.name)

        if header:
            entry.__dict__.update(header)

        self._write_entry(entry)
        self._entries.append(entry)

    #FIXME
    def writable(self):
        """Return True if the stream can be written to."""
        return self.mode is 'wb'

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
    with CpioArchive('test.cpio', 'rb') as cpio:
        print cpio.namelist()


if __name__ == "__main__":
    main()
