# -*- coding: utf-8 -*-

from karton.core import Config, Karton, Task, Resource
from lief import PE
import subprocess
import tempfile
import hashlib
import logging
import lief
import yara
import os

from .__version__ import __version__

log = logging.getLogger(__name__)

yara_rule = """
rule upx_packed_binary 
{
    meta:
        author = "_raw_data_"
        tlp = "WHITE"

        version  = "1.0"
        created = "2021-07-01"
        modified = "2021-07-01"

        description = "Detects UPX packed file"
        
    strings:
        
        $upx0 = { 55 50 58 30 00 00 00 }
        $upx1 = { 55 50 58 31 00 00 00 }
        $upx2 = { 55 50 58 21 }

    condition:
        (
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550)
                and
            (all of ($upx*))
            
        )
}
"""

rule = yara.compile(source=yara_rule)


class RetDecUnpacker(Karton):
    """
    Unpack a given sample with RetDec
    """

    identity = "karton.retdec-unpacker"
    version = __version__
    filters = [
        {"type": "sample", "stage": "recognized"},
    ]

    def __init__(
        self,
        config: Config = None,
        identity: str = None,
    ) -> None:
        super().__init__(config=config, identity=identity)

    def _check_upx(self, sample_path: str) -> bool:
        """Executes YARA with the UPX rule on the provided
        sample

        Args:
            sample_path (str): path to the file

        Returns:
            bool: True if UPX was detected, False otherwise
        """
        with open(sample_path, "rb") as f:
            matches: list = rule.match(data=f.read())

        if matches:
            return True

        return False

    def _extract_file_properties(self, sample_path: str) -> dict:
        """Inspects a PE file, extracting OriginalFilename and
        InternalName file properties

        Args:
            sample_path (str): path to file

        Returns:
            dict: PE extracted properties
            e.g.
                {
                    "OriginalFilename": "cmdcrypt2.exe",
                    "InternalName": "cmdcrypt2.exe",
                }
        """

        try:
            binary = PE.parse(sample_path)
        except lief.exception as err:
            log.error(f"Cannot parse PE file: {err}")
            return False
        else:
            if (
                binary.has_resources
                and binary.resources_manager.has_version
                and binary.resources_manager.version.has_string_file_info
                and binary.resources_manager.version.string_file_info.langcode_items
            ):
                fileinfo = dict(
                    binary.resources_manager.version.string_file_info.langcode_items[
                        0
                    ].items.items()
                )
                fields_to_check = {
                    "OriginalFilename": None,
                    "InternalName": None,
                }

                for field in list(fields_to_check):
                    if s := fileinfo.get(field):
                        if s is not None:
                            fields_to_check[field] = fileinfo.get(
                                field
                            ).decode("utf-8")

                return fields_to_check

    def process_sample(self, sample_path: str) -> str:
        """Executes retdec-unpacker tool on the provided sample

        Args:
            sample_path (str): path to the sample

        Returns:
            str: path to the unpacked sample
        """
        unpacked_sample_path: str = tempfile.mktemp()

        retdec_unpack = subprocess.check_output(
            ["retdec-unpacker", sample_path, "-o", unpacked_sample_path],
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )

        if "successfully unpacked" in retdec_unpack.lower():
            return unpacked_sample_path

        return False

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        if task.headers["type"] == "sample":

            self.log.info(f"Processing sample {sample.metadata['sha256']}")

            with sample.download_temporary_file() as f:
                sample_path = f.name
                if self._check_upx(sample_path):
                    unpacked_sample_path: str = self.process_sample(
                        sample_path
                    )

                    if unpacked_sample_path:

                        child_name = None
                        if file_properties := self._extract_file_properties(
                            unpacked_sample_path
                        ):
                            for (
                                file_property,
                                value,
                            ) in file_properties.items():
                                if value is not None:
                                    log.debug(
                                        f"Using file property '{file_properties}' = {value}"
                                    )
                                    child_name = value
                                    break

                        with open(unpacked_sample_path, "rb") as f:
                            content = f.read()

                            if not child_name:
                                child_name = hashlib.sha256(
                                    content
                                ).hexdigest()

                            child_resource = Resource(
                                name=child_name, content=content
                            )

                        os.remove(unpacked_sample_path)

                        task = Task(
                            headers={"type": "sample", "kind": "raw"},
                            payload={
                                "parent": sample,
                                "sample": child_resource,
                                "tags": ["stage:unpacked"],
                            },
                        )
                        self.send_task(task)
