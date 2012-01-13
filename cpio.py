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


BIN_FORMAT = 070707
OLD_FORMAT = '070707'
NEW_FORMAT = '070701'
CRC_FORMAT = '070702'


def is_cpioarchive(self, path):
    """Quickly check the magic number of a file."""
    with io.open(path, 'rb') as fileobj:
        magic = fileobj.read(6)

    if magic in (NEW_FORMAT, CRC_FORMAT, OLD_FORMAT):
        return True
    if struct.unpack('H', magic[:2])[0] == BIN_FORMAT:
        return True

    return False


def checksum32(bytes):
    """Return a 32-bit unsigned sum of *bytes*."""
    return sum(ord(byte) for byte in bytes) & 0xFFFFFFFF


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
    """
    CpioEntry provides a read-only file-like object, unified to represent
    different cpio formats.
    """

    def __init__(self, cpio, path=None):
        """."""
        self.fileobj = cpio.fileobj
        self.offset = self.fileobj.tell()
        self._position = 0

        self.magic = NEW_FORMAT
        """Magic number of the cpio format."""
        self.dev = 0
        """Number of the device the inode resides on."""
        self.ino = 0
        """Inode number on disk."""
        self.mode = 0
        """Inode protection mode."""
        self.uid = 0
        """User id of the owner."""
        self.gid = 0
        """Group id of the owner."""
        self.nlink = 0
        """Number of links to the inode."""
        self.mtime = 0
        """Time of last modification."""
        self.rdev = 0
        """Number of the device type."""
        self.size = 0
        """Size of the file data in bytes.."""
        self.check = 0
        """32-bit checksum of the file data."""

        self.name = 'TRAILER!!!'
        """Pathname of the entry."""

        if path:
            pstat = os.lstat(path)

            self.dev = pstat.st_dev
            self.ino = pstat.st_ino
            self.mode = pstat.st_mode
            self.uid = pstat.st_uid
            self.gid = pstat.st_gid
            self.nlink = pstat.st_nlink
            self.mtime = pstat.st_mtime
            self.size = pstat.st_size
            self.name = path

            # not available on non-linux systems
            if hasattr(pstat, 'st_rdev'):
                self.rdev = pstat.st_rdev

    def __str__(self):
        """."""
        if self.magic in (NEW_FORMAT, CRC_FORMAT):
            hpad = (4 - (111 + len(self.name)) % 4) % 4

            return ''.join([
                self.magic,
                '{:0>8x}'.format(self.ino),
                '{:0>8x}'.format(self.mode),
                '{:0>8x}'.format(self.uid),
                '{:0>8x}'.format(self.gid),
                '{:0>8x}'.format(self.nlink),
                '{:0>8x}'.format(self.mtime),
                '{:0>8x}'.format(self.size),
                '{:0>8x}'.format(os.major(self.dev)),
                '{:0>8x}'.format(os.minor(self.dev)),
                '{:0>8x}'.format(os.major(self.rdev)),
                '{:0>8x}'.format(os.minor(self.rdev)),
                '{:0>8x}'.format(len(self.name) + 1),
                '{:0>8x}'.format(self.check),
                self.name, '\0',
                ''.rjust(hpad, '\0')])
        elif self.magic == OLD_FORMAT:
            return ''.join([
                self.format,
                '{:0>6o}'.format(self.dev),
                '{:0>6o}'.format(self.ino),
                '{:0>6o}'.format(self.mode),
                '{:0>6o}'.format(self.uid),
                '{:0>6o}'.format(self.gid),
                '{:0>6o}'.format(self.nlink),
                '{:0>6o}'.format(self.rdev),
                '{:0>11o}'.format(self.mtime),
                '{:0>6o}'.format(len(self.name) + 1),
                '{:0>11o}'.format(self.size),
                self.name, '\0'])
        elif self.magic == BIN_FORMAT:
            hpad = (2 - (27 + len(self.name)) % 2) % 2

            return ''.join([
                struct.pack(
                    'H H H H H H H H H H H H H',
                    self.magic,
                    self.dev,
                    self.ino,
                    self.mode,
                    self.uid,
                    self.gid,
                    self.nlink,
                    self.rdev,
                    self.mtime / 256,
                    self.mtime % 256,
                    len(self.name) + 1,
                    self.size / 256,
                    self.size % 256),
                self.name, '\0',
                ''.rjust(hpad, '\0')])

    #FIXME: test
    def read(self, n=-1):
        """FIXME"""
        # seek to current object position, if not already there
        if self.fileobj.tell() != self.offset + self._position:
            self.fileobj.seek(self.offset + self._position)

        # return '' if at EOF for this object
        if self.fileobj.tell() == self.offset + self.size:
            return ''

        #
        if n < 0 or n >= (self.size - self._position):
            data = self.fileobj.read(self.size - self._position)
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

        self._position = min(max(0, self._position), self.size)

    def tell(self):
        """Return the current stream position."""
        return self._position

    def _ino(self):
        return (self.ino, self.dev)

    def _ishardlink(self):
        if self.nlink > 1 and not stat.S_ISDIR(self.mode):
            return True


class CpioArchive(object):
    """
    CpioArchive is a file-like object that acts as a container of CpioEntry
    objects, which in turn allow read or write access to the actual file data.
    """

    def __init__(self, path=None, mode=None, fileobj=None, format=NEW_FORMAT):
        """Constructor for the CpioArchive class.

        Either *fileobj* or *path* must be given a non-trivial value.

        The new class instance is based on *fileobj*, which may be any binary
        file object which supports read(), write() and seek() methods.  If
        *fileobj* is None then *path* will be used to provide a file-object.

        The *mode* argument must be either 'rb' or 'wb'.  The default is 'rb'
        either if *path* is given or if *fileobj* is read-write.

        The *format* argument'
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
            self._read_archive()

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

    def _read_archive(self):
        """."""
        hardlinks = []

        entry = self._read_entry()

        while entry.name != 'TRAILER!!!':
            self._entries.append(entry)
            entry = self._read_entry()

            if entry._ishardlink() and entry.size == 0:
                hardlinks.append(entry)

        #FIXME ### Hardlinks
        for link in hardlinks:
            for entry in self:
                if entry._ino() == link._ino() and entry.size > 0:
                    link.offset = entry.offset
                    link.size = entry.size
                    link.nlink = 1
                    break

    def _read_entry(self):
        """."""
        entry = CpioEntry(self)
        hdr = self.struct.unpack(self.fileobj.read(self.struct.size))

        if self.format in (NEW_FORMAT, CRC_FORMAT):
            entry.magic = hdr[0]
            entry.ino = int(hdr[1], 16)
            entry.mode = int(hdr[2], 16)
            entry.uid = int(hdr[3], 16)
            entry.gid = int(hdr[4], 16)
            entry.nlink = int(hdr[5], 16)
            entry.mtime = int(hdr[6], 16)
            entry.size = int(hdr[7], 16)
            entry.dev = os.makedev(int(hdr[8], 16), int(hdr[9], 16))
            entry.rdev = os.makedev(int(hdr[10], 16), int(hdr[11], 16))
            namesize = int(hdr[12], 16)
            entry.check = int(hdr[13], 16)

            # the header is NUL padded to a multiple of 4-bytes
            hpad = (4 - (110 + namesize) % 4) % 4
            dpad = (4 - entry.size % 4) % 4
        elif self.format == OLD_FORMAT:
            entry.magic = hdr[0]
            entry.dev = int(hdr[1], 8)
            entry.ino = int(hdr[2], 8)
            entry.mode = int(hdr[3], 8)
            entry.uid = int(hdr[4], 8)
            entry.gid = int(hdr[5], 8)
            entry.nlink = int(hdr[6], 8)
            entry.rdev = int(hdr[7], 8)
            entry.mtime = int(hdr[8], 8)
            namesize = int(hdr[9], 8)
            entry.size = int(hdr[10], 8)

            hpad, dpad = 0, 0
        elif self.format == BIN_FORMAT:
            entry.magic = hdr[0]
            entry.dev = hdr[1]
            entry.ino = hdr[2]
            entry.mode = hdr[3]
            entry.uid = hdr[4]
            entry.gid = hdr[5]
            entry.nlink = hdr[6]
            entry.rdev = hdr[7]
            entry.mtime = hdr[8] * 256 + hdr[9]
            namesize = hdr[10]
            entry.size = hdr[11] * 256 + hdr[12]

            # the header is NUL padded to a multiple of 2-bytes
            hpad = (2 - (26 + namesize) % 2) % 2
            dpad = (2 - entry.size % 2) % 2

        # Read the entry name; exclude the trailing NUL byte and padding
        entry.name = self.fileobj.read(namesize + hpad)[:-1 + -hpad]
        entry.offset = self.fileobj.tell()

        # Checksum regular files, otherwise read past the data and return
        if self.format == CRC_FORMAT and stat.S_ISREG(entry.mode):
            data = self.fileobj.read(entry.size + dpad)[:-dpad]

            if checksum32(data) != entry.check:
                raise ChecksumError(entry.name)
        else:
            self.fileobj.read(entry.size + dpad)

        return entry

    def _read_magic(self):
        """."""
        if self.fileobj.readable():
            magic = self.fileobj.read(6)
            self.fileobj.seek(0)

            if magic == '':
                return None
            if magic in (NEW_FORMAT, CRC_FORMAT, OLD_FORMAT):
                return magic
            if struct.unpack('H', magic[:2])[0] == BIN_FORMAT:
                return BIN_FORMAT

            raise HeaderError('unknown format')
        else:
            return None

    def _write_entry(self, entry, data=None):
        """Write *entry*, which should be a CpioEntry object."""
#        if path:
#            # write the data; regular files and symbolic links only
#            if stat.S_ISREG(self.mode):
#                with io.open(path, 'rb') as pathobj:
#                    data = pathobj.read()
#            elif stat.S_IFLNK(self.mode):
#                # The target of a symbolic link is stored as file data
#                data = os.readlink(path)

#            # checksum
#            if self.magic == CRC_FORMAT and stat.S_ISREG(self.mode):
#                self.check = checksum32(data)

#            self.fileobj.write(data + ''.rjust(dpad, '\0'))

        if data is not None:
            if stat.S_ISREG(entry.mode) or stat.S_ISLNK(entry.mode):
                pass
            if self.checksum and stat.S_ISREG(entry.mode):
                entry.check = checksum32(data)

        self.fileobj.write(str(entry))

        if data:
            self.fileobj.write(data)

    def close(self):
        """Flush and close this stream."""
        if self.fileobj is None:
            return

        self.flush()
        self.fileobj = None

    def closed(self):
        """True if the stream is closed."""
        return self.fileobj is None

    #FIXME: just broken, OS support
    def extract(self, entry, path=None):
        """Extract an entry from the archive.

        The *name* argument should be the entry's pathname.

        The *path* argument is a path to a directory, defaulting to the
        current working directory, where the file will be extracted.  When
        extracting a single file
        """
        # get entry by name
        if not isinstance(entry, CpioEntry):
            for candidate in self:
                if candidate.name == entry:
                    entry = candidate

        path = os.path.join(path or os.getcwd(), entry.name)

        # Create a file on disk for the appropriate type
        if stat.S_ISDIR(entry.mode):
            os.mkdir(path, entry.mode & 0777)
        elif stat.S_ISREG(entry.mode):
            with io.open(path, 'wb') as pathobj:
                entry.seek(0)
                pathobj.write(entry.read())
        # Symbolic link targets are stored as file data
        elif stat.S_ISLNK(entry.mode):
            entry.seek(0)
            os.symlink(entry.read(), path)
        #FIXME: All other types will be created with os.mknod()
        else:
            os.mknod(path, entry.mode, entry.dev)

    def extractall(self, path=None):
        """."""
        for entry in self:
            self.extract(entry, path)

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
        return self._format

    @format.setter
    def format(self, value):
        """."""
        if value in (NEW_FORMAT, CRC_FORMAT):
            self.struct = struct.Struct('6s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s')
        elif value == OLD_FORMAT:
            self.struct = struct.Struct('6s 6s 6s 6s 6s 6s 6s 6s 11s 6s 11s')
        elif value == BIN_FORMAT:
            self.struct = struct.Struct('H H H H H H H H H H H H H')
        else:
            raise Error('unsupported format')

        self._format = value

    def namelist(self):
        """Return a list of entry names."""
        return [entry.name for entry in self]

    def write(self, path, **hdr):
        """."""
        pass


def main():
    """."""
    with CpioArchive('test.cpio', 'rb') as cpio:
        #cpio.extractall('test')
        print cpio.namelist()


if __name__ == "__main__":
    main()
