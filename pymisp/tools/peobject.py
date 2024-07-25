#!/usr/bin/env python3

from __future__ import annotations

import logging

from base64 import b64encode
from datetime import datetime
from hashlib import md5, sha1, sha256, sha512
from io import BytesIO
from pathlib import Path
from typing import Any

from . import FileObject
from .abstractgenerator import AbstractMISPObjectGenerator
from ..exceptions import InvalidMISPObject

import lief
import lief.PE

try:
    import pydeep  # type: ignore
    HAS_PYDEEP = True
except ImportError:
    HAS_PYDEEP = False

logger = logging.getLogger('pymisp')


def make_pe_objects(lief_parsed: lief.PE.Binary,
                    misp_file: FileObject,
                    standalone: bool = True,
                    default_attributes_parameters: dict[str, Any] = {}) -> tuple[FileObject, PEObject, list[PESectionObject]]:
    pe_object = PEObject(parsed=lief_parsed, standalone=standalone, default_attributes_parameters=default_attributes_parameters)
    misp_file.add_reference(pe_object.uuid, 'includes', 'PE indicators')
    pe_sections = []
    for s in pe_object.sections:
        pe_sections.append(s)
    return misp_file, pe_object, pe_sections


class PEObject(AbstractMISPObjectGenerator):

    __pe: lief.PE.Binary

    __characteristics_mapping: dict[int, str] = {
        1: "RELOCS_STRIPPED",
        2: "EXECUTABLE_IMAGE",
        4: "LINE_NUMS_STRIPPED",
        8: "LOCAL_SYMS_STRIPPED",
        16: "AGGRESSIVE_WS_TRIM",
        32: "LARGE_ADDRESS_AWARE",
        128: "BYTES_REVERSED_LO",
        256: "NEED_32BIT_MACHINE",
        512: "DEBUG_STRIPPED",
        1024: "REMOVABLE_RUN_FROM_SWAP",
        2048: "NET_RUN_FROM_SWAP",
        4096: "SYSTEM",
        8192: "DLL",
        16384: "UP_SYSTEM_ONLY",
        32768: "BYTES_REVERSED_HI"
    }
    __machine_type_mapping: dict[str, str] = {
        "1d3": "AM33",
        "8664": "AMD64",
        "1c0": "ARM",
        "aa64": "ARM64",
        "1c4": "ARMNT",
        "ebc": "EBC",
        "14c": "I386",
        "200": "IA64",
        "9041": "M32R",
        "266": "MIPS16",
        "366": "MIPSFPU",
        "466": "MIPSFPU16",
        "1f0": "POWERPC",
        "1f1": "POWERPCFP",
        "166": "R4000",
        "1a2": "SH3",
        "1a3": "SH3DSP",
        "1a6": "SH4",
        "1a8": "SH5",
        "1c2": "THUMB",
        "0": "UNKNOWN",
        "169": "WCEMIPSV2"
    }


    def __init__(self, parsed: lief.PE.Binary | None = None,  # type: ignore[no-untyped-def]
                 filepath: Path | str | None = None,
                 pseudofile: BytesIO | list[int] | None = None,
                 **kwargs) -> None:
        """Creates an PE object, with lief"""
        super().__init__('pe', **kwargs)
        if not HAS_PYDEEP:
            logger.warning("pydeep is missing, please install pymisp this way: pip install pymisp[fileobjects]")
        if pseudofile:
            if isinstance(pseudofile, BytesIO):
                p = lief.PE.parse(obj=pseudofile)
            elif isinstance(pseudofile, bytes):
                p = lief.PE.parse(raw=list(pseudofile))
            elif isinstance(pseudofile, list):
                p = lief.PE.parse(raw=pseudofile)
            else:
                raise InvalidMISPObject(f'Pseudo file can be BytesIO or bytes got {type(pseudofile)}')
            if not p:
                raise InvalidMISPObject('Unable to parse pseudofile')
            self.__pe = p
        elif filepath:
            if p := lief.PE.parse(filepath):
                self.__pe = p
            else:
                raise InvalidMISPObject(f'Unable to parse {filepath}')
        elif parsed:
            # Got an already parsed blob
            if isinstance(parsed, lief.PE.Binary):
                self.__pe = parsed
            else:
                raise InvalidMISPObject(f'Not a lief.PE.Binary: {type(parsed)}')
        self.generate_attributes()

    def _is_exe(self) -> bool:
        if not self._is_dll() and not self._is_driver():
            return self.__pe.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.EXECUTABLE_IMAGE)
        return False

    def _is_dll(self) -> bool:
        return self.__pe.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)

    def _is_driver(self) -> bool:
        # List from pefile
        system_DLLs = {'ntoskrnl.exe', 'hal.dll', 'ndis.sys', 'bootvid.dll', 'kdcom.dll'}
        if system_DLLs.intersection([imp.lower() for imp in self.__pe.libraries]):
            return True
        return False

    def _get_pe_type(self) -> str:
        if self._is_dll():
            return 'dll'
        elif self._is_driver():
            return 'driver'
        elif self._is_exe():
            return 'exe'
        else:
            return 'unknown'

    def generate_attributes(self) -> None:
        self.add_attribute('type', value=self._get_pe_type())
        # General information
        header = self.__pe.header
        self.add_attribute('entrypoint-address', value=self.__pe.entrypoint)
        self.add_attribute('compilation-timestamp', value=datetime.utcfromtimestamp(header.time_date_stamps).isoformat())
        self.add_attribute('imphash', value=lief.PE.get_imphash(self.__pe, lief.PE.IMPHASH_MODE.PEFILE))
        self.add_attribute('authentihash', value=self.__pe.authentihash_sha256.hex())
        machine_type_hex = f'{header.machine.value:x}'
        machine_type = self.__machine_type_mapping.get(machine_type_hex)
        if machine_type is not None:
            self.add_attribute('machine-type', value=machine_type)
        self.add_attribute('machine-type-hex', value=machine_type_hex)
        self.add_attribute('pointer-to-symbol-table', value=f'{header.pointerto_symbol_table:x}')
        self.add_attribute('number-of-symbols', value=header.numberof_symbols)
        self.add_attribute('size-of-optional-header', value=header.sizeof_optional_header)
        for characteristic_int in header.characteristics_list:
            characteristic = self.__characteristics_mapping.get(characteristic_int)
            if characteristic is not None:
                self.add_attribute('characteristics', value=characteristic)
        self.add_attribute('characteristics-hex', value=f'{header.characteristics:x}')
        r_manager = self.__pe.resources_manager
        if isinstance(r_manager, lief.PE.ResourcesManager):
            version = r_manager.version
            if isinstance(version, lief.PE.ResourceVersion) and version.string_file_info is not None:
                fileinfo = dict(version.string_file_info.langcode_items[0].items.items())
                self.add_attribute('original-filename', value=fileinfo.get('OriginalFilename'))
                self.add_attribute('internal-filename', value=fileinfo.get('InternalName'))
                self.add_attribute('file-description', value=fileinfo.get('FileDescription'))
                self.add_attribute('file-version', value=fileinfo.get('FileVersion'))
                self.add_attribute('product-name', value=fileinfo.get('ProductName'))
                self.add_attribute('product-version', value=fileinfo.get('ProductVersion'))
                self.add_attribute('company-name', value=fileinfo.get('CompanyName'))
                self.add_attribute('legal-copyright', value=fileinfo.get('LegalCopyright'))
                self.add_attribute('lang-id', value=version.string_file_info.langcode_items[0].key)
        # Optional Header
        self.__pe.optional_header = PEOptionalHeaderObject(
            self.__pe.optional_header, standalone=self._standalone,
            default_attributes_parameters=self._default_attributes_parameters
        )
        # Sections
        self.sections = []
        if self.__pe.sections:
            pos = 0
            for section in self.__pe.sections:
                if not section.name and not section.size:
                    # Skip section if name is none AND size is 0.
                    continue
                s = PESectionObject(section, standalone=self._standalone, default_attributes_parameters=self._default_attributes_parameters)
                self.add_reference(s.uuid, 'includes', f'Section {pos} of PE')
                if ((self.__pe.entrypoint >= section.virtual_address)
                        and (self.__pe.entrypoint < (section.virtual_address + section.virtual_size))):
                    if isinstance(section.name, bytes):
                        section_name = section.name.decode()
                    else:
                        section_name = section.name
                    self.add_attribute('entrypoint-section-at-position', value=f'{section_name}|{pos}')
                pos += 1
                self.sections.append(s)
        self.add_attribute('number-sections', value=len(self.sections))
        # Signatures
        self.certificates = []
        self.signers = []
        for sign in self.__pe.signatures:
            for c in sign.certificates:
                cert_obj = PECertificate(c)
                self.add_reference(cert_obj.uuid, 'signed-by')
                self.certificates.append(cert_obj)
            for s_info in sign.signers:
                signer_obj = PESigners(s_info)
                self.add_reference(signer_obj.uuid, 'signed-by')
                self.signers.append(signer_obj)


class PECertificate(AbstractMISPObjectGenerator):

    def __init__(self, certificate: lief.PE.x509, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__('x509')
        self.__certificate = certificate
        self.generate_attributes()

    def generate_attributes(self) -> None:
        self.add_attribute('issuer', value=self.__certificate.issuer)
        self.add_attribute('serial-number', value=self.__certificate.serial_number)
        if len(self.__certificate.valid_from) == 6:
            self.add_attribute('validity-not-before',
                               value=datetime(year=self.__certificate.valid_from[0],
                                              month=self.__certificate.valid_from[1],
                                              day=self.__certificate.valid_from[2],
                                              hour=self.__certificate.valid_from[3],
                                              minute=self.__certificate.valid_from[4],
                                              second=self.__certificate.valid_from[5]))
        if len(self.__certificate.valid_to) == 6:
            self.add_attribute('validity-not-after',
                               value=datetime(year=self.__certificate.valid_to[0],
                                              month=self.__certificate.valid_to[1],
                                              day=self.__certificate.valid_to[2],
                                              hour=self.__certificate.valid_to[3],
                                              minute=self.__certificate.valid_to[4],
                                              second=self.__certificate.valid_to[5]))
        self.add_attribute('version', value=self.__certificate.version)
        self.add_attribute('subject', value=self.__certificate.subject)
        self.add_attribute('signature_algorithm', value=self.__certificate.signature_algorithm)
        self.add_attribute('raw-base64', value=b64encode(self.__certificate.raw))


class PEOptionalHeaderObject(AbstractMISPObjectGenerator):

    __characteristics_mapping: dict[int, str] = {
        32: "HIGH_ENTROPY_VA",
        64: "DYNAMIC_BASE",
        128: "FORCE_INTEGRITY",
        256: "NX_COMPAT",
        512: "NO_ISOLATION",
        1024: "NO_SEH",
        2048: "NO_BIND",
        4096: "APPCONTAINER",
        8192: "WDM_DRIVER",
        16384: "GUARD_CF",
        32768: "TERMINAL_SERVER_AWARE",
    }
    __magic_mapping: dict[str, str] = {
        '10b': 'PE32',
        '20b': 'PE32_PLUS'
    }
    __subsystem_mapping: dict[str, str] = {
        "a": "EFI_APPLICATION",
        "b": "EFI_BOOT_SERVICE_DRIVER",
        "d": "EFI_ROM",
        "c": "EFI_RUNTIME_DRIVER",
        "1": "NATIVE",
        "8": "NATIVE_WINDOWS",
        "5": "OS2_CUI",
        "7": "POSIX_CUI",
        "0": "UNKNOWN",
        "10": "WINDOWS_BOOT_APPLICATION",
        "9": "WINDOWS_CE_GUI",
        "3": "WINDOWS_CUI",
        "2": "WINDOWS_GUI",
        "e": "XBOX"
    }

    def __init__(self, optional_header: lief.PE.OptionalHeader, **kwargs) -> None:
        super().__init__('pe-optional-header')
        self.__optional_header = optional_header
        self.generate_attributes()

    def generate_attributes(self) -> None:
        self.add_attribute('entrypoint-address', value=self.__optional_header.addressof_entrypoint)
        self.add_attribute('base-of-code', value=self.__optional_header.baseof_code)
        self.add_attribute('base-of-data', value=self.__optional_header.baseof_data)
        self.add_attribute('checksum', value=f'{self.__optional_header.checksum:x}')
        for characteristic_int in self.__optional_header.dll_characteristics_list:
            characteristic = self.__characteristics_mapping.get(characteristic_int)
            if characteristic is not None:
                self.add_attribute('dll-characteristics', value=characteristic)
        self.add_attribute('dll-characteristics-hex', value=f'{self.__optional_header.dll_characteristics:x}')
        self.add_attribute('file-alignment', value=self.__optional_header.file_alignment)
        self.add_attribute('image-base', value=self.__optional_header.imagebase)
        magic_hex = f'{self.__optional_header.magic.value:x}'
        magic = self.__magic_mapping.get(magic_hex)
        if magic is not None:
            self.add_attribute('magic', value=magic)
        self.add_attribute('magic', value=magic_hex)
        self.add_attribute('loader-flags', value=f'{self.__optional_header.loader_flags:x}')
        self.add_attribute('major-image-version', value=self.__optional_header.major_image_version)
        self.add_attribute('major-linker-version', value=self.__optional_header.major_linker_version)
        self.add_attribute('major-os-version', value=self.__optional_header.major_operating_system_version)
        self.add_attribute('major-subsystem-version', value=self.__optional_header.major_subsystem_version)
        self.add_attribute('minor-image-version', value=self.__optional_header.minor_image_version)
        self.add_attribute('minor-linker-version', value=self.__optional_header.minor_linker_version)
        self.add_attribute('minor-os-version', value=self.__optional_header.minor_operating_system_version)
        self.add_attribute('minor-subsystem-version', value=self.__optional_header.minor_subsystem_version)
        self.add_attribute('number-of-rva-and-size', value=self.__optional_header.numberof_rva_and_size)
        self.add_attribute('section-alignment', value=self.__optional_header.section_alignment)
        self.add_attribute('size-of-code', value=self.__optional_header.sizeof_code)
        self.add_attribute('size-of-headers', value=self.__optional_header.sizeof_headers)
        self.add_attribute('size-of-heap-commit', value=self.__optional_header.sizeof_heap_commit)
        self.add_attribute('size-of-heap-reserve', value=self.__optional_header.sizeof_heap_reserve)
        self.add_attribute('size-of-image', value=self.__optional_header.sizeof_image)
        self.add_attribute('size-of-initialised-data', value=self.__optional_header.sizeof_initialized_data)
        self.add_attribute('size-of-stack-commit', value=self.__optional_header.sizeof_stack_commit)
        self.add_attribute('size-of-stack-reserve', value=self.__optional_header.sizeof_stack_reserve)
        self.add_attribute('size-of-uninitialised-data', value=self.__optional_header.sizeof_uninitialized_data)
        subsystem_hex = f'{self.__optional_header.subsystem.value:x}'
        subsystem = self.__subsystem_mapping.get(subsystem_hex)
        if subsystem is not None:
            self.add_attribute('subsystem', value=subsystem)
        self.add_attribute('subsystem', value=subsystem_hex)
        self.add_attribute('win32-version-value', value=f'{self.__optional_header.win32_version_value:x}')


class PESigners(AbstractMISPObjectGenerator):

    def __init__(self, signer: lief.PE.SignerInfo, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__('authenticode-signerinfo')
        self.__signer = signer
        self.generate_attributes()

    def generate_attributes(self) -> None:
        self.add_attribute('issuer', value=self.__signer.issuer)
        self.add_attribute('serial-number', value=self.__signer.serial_number)
        self.add_attribute('version', value=self.__signer.version)
        self.add_attribute('digest_algorithm', value=str(self.__signer.digest_algorithm))
        self.add_attribute('encryption_algorithm', value=str(self.__signer.encryption_algorithm))
        self.add_attribute('digest-base64', value=b64encode(self.__signer.encrypted_digest))
        info: lief.PE.SpcSpOpusInfo = self.__signer.get_attribute(lief.PE.Attribute.TYPE.SPC_SP_OPUS_INFO)  # type: ignore[assignment]
        if info:
            self.add_attribute('program-name', value=info.program_name)
            self.add_attribute('url', value=info.more_info)


class PESectionObject(AbstractMISPObjectGenerator):

    def __init__(self, section: lief.PE.Section, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """Creates an PE Section object. Object generated by PEObject."""
        super().__init__('pe-section')
        self.__section = section
        self.__data = bytes(self.__section.content)
        self.generate_attributes()

    def generate_attributes(self) -> None:
        self.add_attribute('name', value=self.__section.name)
        self.add_attribute('size-in-bytes', value=self.__section.size)
        if int(self.__section.size) > 0:
            # zero-filled sections can create too many correlations
            to_ids = float(self.__section.entropy) > 0
            disable_correlation = not to_ids
            self.add_attribute('entropy', value=self.__section.entropy)
            self.add_attribute('md5', value=md5(self.__data).hexdigest(), disable_correlation=disable_correlation, to_ids=to_ids)
            self.add_attribute('sha1', value=sha1(self.__data).hexdigest(), disable_correlation=disable_correlation, to_ids=to_ids)
            self.add_attribute('sha256', value=sha256(self.__data).hexdigest(), disable_correlation=disable_correlation, to_ids=to_ids)
            self.add_attribute('sha512', value=sha512(self.__data).hexdigest(), disable_correlation=disable_correlation, to_ids=to_ids)
            if HAS_PYDEEP and float(self.__section.entropy) > 0:
                if self.__section.name == '.rsrc':
                    # ssdeep of .rsrc creates too many correlations
                    disable_correlation = True
                    to_ids = False
                self.add_attribute('ssdeep', value=pydeep.hash_buf(self.__data).decode(), disable_correlation=disable_correlation, to_ids=to_ids)
