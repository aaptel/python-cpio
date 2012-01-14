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

BIN_STRUCT = 'H H H H H H H H HH H HH'
OLD_STRUCT = '6s 6s 6s 6s 6s 6s 6s 6s 11s 6s 11s'
NEW_STRUCT = '6s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s'


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

    __slots__ = [
        'fileobj',
        'filepos',
        'offset',
        'dev',
        'ino',
        'mode',
        'uid',
        'gid',
        'nlink',
        'mtime',
        'rdev',
        'size',
        'check',
        'name']

    def __init__(self, fileobj):
        """."""
        self.fileobj = fileobj
        self.filepos = self.fileobj.tell()
        self.offset = 0

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
        """Size of the file data in bytes."""
        self.check = 0
        """32-bit checksum of the file data (New CRC format only)."""
        self.name = 'TRAILER!!!'
        """Pathname of the entry."""

    #FIXME: test
    def read(self, n=-1):
        """FIXME"""
        # seek to current object position, if not already there
        if self.fileobj.tell() != self.filepos + self.offset:
            self.fileobj.seek(self.filepos + self.offset)

        # return '' if at EOF for this object
        if self.fileobj.tell() == self.filepos + self.size:
            return ''

        #
        if n < 0 or n >= (self.size - self.offset):
            data = self.fileobj.read(self.size - self.offset)
        else:
            data = self.fileobj.read(n)

        self.offset += len(data)

        return data

    def seek(self, offset, whence=0):
        """
        Change the stream position to the given byte *offset*.  *offset* is
        interpreted relative to the position indicated by *whence*. Values for
        *whence* are synonymous to those in the :mod:`io` module.
        """
        if whence == 0:
            self.offset = offset
        elif whence == 1:
            self.offset += offset
        elif whence == 2:
            self.offset -= offset

        self.offset = min(max(0, self.offset), self.size)

    def tell(self):
        """Return the current stream position."""
        return self.offset

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

    def _fix_hardlinks(self):
        """Amend the file metrics of hardlink entries."""
        if self.format in (NEW_FORMAT, CRC_FORMAT):
            hardlinks = [entry for entry in self if entry._ishardlink()]

            inodes = [entry for entry in hardlinks if entry.size > 0]
            links = [entry for entry in hardlinks if entry.size == 0]

            for inode in inodes:
                for link in links:
                    if link.ino == inode.ino and link.dev == inode.dev:
                        link.filepos = inode.filepos
                        link.size = inode.size
                        link.nlink = 1

    def _read_archive(self):
        """Read entries until a trailer entry is seen."""
        entry = self._read_entry()

        while entry.name != 'TRAILER!!!':
            self._entries.append(entry)
            entry = self._read_entry()

        self._fix_hardlinks()

    def _read_entry(self):
        """."""
        entry = CpioEntry(self.fileobj)

        try:
            hdr = self.struct.unpack(self.fileobj.read(self.struct.size))
        except struct.error:
            raise HeaderError('incomplete header')

        if self.format in (NEW_FORMAT, CRC_FORMAT):
            #entry.magic = hdr[0]
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

            # the header and data are NUL padded to a multiple of 4-bytes
            hpad = (4 - (110 + namesize) % 4) % 4
            dpad = (4 - entry.size % 4) % 4
        elif self.format == OLD_FORMAT:
            #entry.magic = hdr[0]
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
            #entry.magic = hdr[0]
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

            # the header and data are NUL padded to a multiple of 2-bytes
            hpad = (2 - (26 + namesize) % 2) % 2
            dpad = (2 - entry.size % 2) % 2

        # Read the entry name; exclude the trailing NUL byte and padding
        entry.name = self.fileobj.read(namesize + hpad)[:-1 + -hpad]
        entry.filepos = self.fileobj.tell()

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

    def _write_entry(self, entry, data=None):
        """Write *entry*, which should be a CpioEntry object."""
        if self.format in (NEW_FORMAT, CRC_FORMAT):
            hpad = (4 - (111 + len(entry.name)) % 4) % 4
            dpad = (4 - entry.size % 4) % 4

            self.fileobj.write(
                ''.join([
                    self.format,
                    '{:0>8x}'.format(entry.ino),
                    '{:0>8x}'.format(entry.mode),
                    '{:0>8x}'.format(entry.uid),
                    '{:0>8x}'.format(entry.gid),
                    '{:0>8x}'.format(entry.nlink),
                    '{:0>8x}'.format(entry.mtime),
                    '{:0>8x}'.format(entry.size),
                    '{:0>8x}'.format(os.major(entry.dev)),
                    '{:0>8x}'.format(os.minor(entry.dev)),
                    '{:0>8x}'.format(os.major(entry.rdev)),
                    '{:0>8x}'.format(os.minor(entry.rdev)),
                    '{:0>8x}'.format(len(entry.name) + 1),
                    '{:0>8x}'.format(entry.check),
                    entry.name, '\0',
                    ''.rjust(hpad, '\0')]))
        elif self.format == OLD_FORMAT:
            hpad, dpad = 0, 0

            entry.fileobj.write(
                ''.join([
                    self.format,
                    '{:0>6o}'.format(entry.dev),
                    '{:0>6o}'.format(entry.ino),
                    '{:0>6o}'.format(entry.mode),
                    '{:0>6o}'.format(entry.uid),
                    '{:0>6o}'.format(entry.gid),
                    '{:0>6o}'.format(entry.nlink),
                    '{:0>6o}'.format(entry.rdev),
                    '{:0>11o}'.format(entry.mtime),
                    '{:0>6o}'.format(len(entry.name) + 1),
                    '{:0>11o}'.format(entry.size),
                    entry.name, '\0']))
        elif self.format == BIN_FORMAT:
            hpad = (2 - (27 + len(entry.name)) % 2) % 2
            dpad = (2 - entry.size % 2) % 2

            self.fileobj.write(
                ''.join([
                    entry.struct.pack(
                        self.format,
                        entry.dev,
                        entry.ino,
                        entry.mode,
                        entry.uid,
                        entry.gid,
                        entry.nlink,
                        entry.rdev,
                        entry.mtime / 256,
                        entry.mtime % 256,
                        len(entry.name) + 1,
                        entry.size / 256,
                        entry.size % 256),
                    entry.name, '\0',
                    ''.rjust(hpad, '\0')]))

        if data:
            entry.filepos = self.fileobj.tell()
            self.fileobj.write(data + ''.rjust(dpad, '\0'))

    #FIXME
    def close(self):
        """Flush and close this stream."""
        if self.fileobj is None:
            return

        if self.fileobj.writable():
            self._write_entry(CpioEntry(self.fileobj))

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

    #FIXME
    def flush(self):
        """Write a trailer entry, if writable(), and flush the file-object"""
        self.fileobj.flush()

    @property
    def format(self):
        """."""
        return self._format

    #FIXME
    @format.setter
    def format(self, value):
        """."""
        if len(self._entries) > 0:
            raise Error('can not change format')
        if value in (NEW_FORMAT, CRC_FORMAT):
            self.struct = struct.Struct(NEW_STRUCT)
        elif value == OLD_FORMAT:
            self.struct = struct.Struct(OLD_STRUCT)
        elif value == BIN_FORMAT:
            self.struct = struct.Struct(BIN_STRUCT)
        else:
            raise Error('unsupported format')

        self._format = value

    def namelist(self):
        """Return a list of entry names."""
        return [entry.name for entry in self]

    #FIXME
    def write(self, path, **kwargs):
        """."""
        entry = CpioEntry(self.fileobj)
        pstat = os.lstat(path)

        entry.dev = pstat.st_dev
        entry.ino = pstat.st_ino
        entry.mode = pstat.st_mode
        entry.uid = pstat.st_uid
        entry.gid = pstat.st_gid
        entry.nlink = pstat.st_nlink
        entry.mtime = pstat.st_mtime
        entry.size = pstat.st_size
        entry.name = path

        # not available on non-linux systems
        if hasattr(pstat, 'st_rdev'):
            entry.rdev = pstat.st_rdev

        # write the data; regular files and symbolic links only
        if stat.S_ISREG(self.mode):
            with io.open(path, 'rb') as pathobj:
                # compute the `check` header field, if applicable
                if self.format == CRC_FORMAT:
                    data = pathobj.read()
                    entry.check = checksum32(data)
                    self._write_entry(entry, data)
                else:
                    self._write_entry(entry, pathobj.read())
        # The target of a symbolic link is stored as file data
        elif stat.S_IFLNK(self.mode):
            self._write_entry(entry, os.readlink(path))

        self._entries.append(entry)


#FIXME: command line interface
def main():
    """."""
    with CpioArchive('test.ocpio', 'rb') as cpio:
        #cpio.extractall('test')
        print cpio.namelist()


if __name__ == "__main__":
    main()
