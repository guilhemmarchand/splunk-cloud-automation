#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"

import os
import tarfile
import logging


# context manager
class cd:
    """Context manager for changing the current working directory"""

    def __init__(self, newPath):
        self.newPath = os.path.expanduser(newPath)

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)


def create_tarfile_excluding_large_files(
    app_directory, tar_file, exclude_large_files, large_file_size_mb
):
    """
    Create a tar.gz file excluding files larger than the specified size if required, and return a list of excluded files.

    Parameters:
    - app_directory: The directory of the app to be archived.
    - tar_file: The output tar.gz file path.
    - exclude_large_files: Boolean indicating whether to exclude large files.
    - large_file_size_mb: The size threshold in MB for excluding large files.

    Returns:
    - A list of dictionaries, each containing the 'path' and 'size_mb' of excluded files.
    """
    large_file_size_bytes = large_file_size_mb * 1024 * 1024  # Convert MB to bytes
    excluded_files = []

    try:
        with tarfile.open(tar_file, mode="w:gz") as tar:
            for root, dirs, files in os.walk(app_directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_size_bytes = os.path.getsize(file_path)
                    if exclude_large_files and file_size_bytes > large_file_size_bytes:
                        logging.info(f"Excluding large file: {file_path}")
                        excluded_files.append(
                            {
                                "path": file_path,
                                "size_mb": round(file_size_bytes / (1024 * 1024), 3),
                            }
                        )
                        continue
                    tar.add(
                        file_path,
                        arcname=os.path.relpath(file_path, start=app_directory),
                    )

    except Exception as e:
        logging.error(f"Error creating tar.gz file: {e}")
        raise e

    return excluded_files
