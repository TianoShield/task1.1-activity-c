## @file HBFAplus.dsc
#  HBFAplus Platform Description File.
#
#  Standalone, protocol-level EDK2 fuzzing framework.
#  Independent of HBFA - all required libraries and headers are included.
#
#  Architecture:
#    MockProtocols/ - Shared mock protocol implementations (installed on gFuzzHandle)
#    FuzzHarness/   - Self-contained harnesses (each creates its own mock objects)
#    HostLib/        - Host-compatible UEFI library implementations (libc-based)
#
#  Usage:
#    build -p HBFAplus/HBFAplus.dsc -m HBFAplus/FuzzHarness/<path>/TestXxx.inf -a X64 -t AFL
#
#  Copyright (c) 2024-2026, HBFAplus Contributors. All rights reserved.
#  SPDX-License-Identifier: BSD-2-Clause-Patent
##

[Defines]
  PLATFORM_NAME                  = HBFAplusPkg
  PLATFORM_GUID                  = ABCD1234-5678-90EF-ABCD-1234567890AB
  PLATFORM_VERSION               = 1.0
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/HBFAplusPkg
  SUPPORTED_ARCHITECTURES        = IA32|X64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT
  DEFINE TEST_WITH_INSTRUMENT = FALSE
  DEFINE HBFAPLUS_PATCH_DXE_CONSTRUCTORS = TRUE

#=============================================================================
# Library Classes
#=============================================================================

[LibraryClasses]
  #---------------------------------------------------------------------------
  # Host Libraries (HBFAplus/HostLib) - libc-based UEFI service implementations
  #---------------------------------------------------------------------------
  BaseLib|HBFAplus/HostLib/BaseLibHost/BaseLibHost.inf
  BaseMemoryLib|HBFAplus/HostLib/BaseMemoryLibHost/BaseMemoryLibHost.inf
  MemoryAllocationLib|HBFAplus/HostLib/MemoryAllocationLibHost/MemoryAllocationLibHost.inf
  DebugLib|HBFAplus/HostLib/DebugLibHost/DebugLibHost.inf
  UefiBootServicesTableLib|HBFAplus/HostLib/UefiBootServicesTableLibHost/UefiBootServicesTableLibHost.inf
  UefiRuntimeServicesTableLib|HBFAplus/HostLib/UefiRuntimeServicesTableLibHost/UefiRuntimeServicesTableLibHost.inf
  DevicePathLib|HBFAplus/HostLib/UefiDevicePathLibHost/UefiDevicePathLibHost.inf
  CacheMaintenanceLib|HBFAplus/HostLib/BaseCacheMaintenanceLibHost/BaseCacheMaintenanceLibHost.inf
  TimerLib|HBFAplus/HostLib/BaseTimerLibHost/BaseTimerLibHost.inf
  HobLib|HBFAplus/HostLib/HobLibHost/HobLibHost.inf
  DxeServicesTableLib|HBFAplus/HostLib/DxeServicesTableLibHost/DxeServicesTableLibHost.inf
  SmmServicesTableLib|HBFAplus/HostLib/SmmServicesTableLibHost/SmmServicesTableLibHost.inf
  MmServicesTableLib|HBFAplus/HostLib/SmmServicesTableLibHost/SmmServicesTableLibHost.inf
  SmmMemLib|HBFAplus/HostLib/SmmMemLibHost/SmmMemLibHost.inf
  PeiServicesLib|MdePkg/Library/PeiServicesLib/PeiServicesLib.inf
  PeiServicesTablePointerLib|HBFAplus/HostLib/PeiServicesTablePointerLibHost/PeiServicesTablePointerLibHost.inf
  UefiDriverEntryPoint|HBFAplus/HostLib/UefiDriverEntryPointHost/UefiDriverEntryPointHost.inf
  PeimEntryPoint|HBFAplus/HostLib/PeimEntryPointHost/PeimEntryPointHost.inf
  SynchronizationLib|HBFAplus/HostLib/SimpleSynchronizationLib/SimpleSynchronizationLib.inf

  #---------------------------------------------------------------------------
  # Fuzzing Infrastructure
  #---------------------------------------------------------------------------
  FuzzContextLib|HBFAplus/HostLib/FuzzContextLib/FuzzContextLib.inf
  RegisterFilterLib|HBFAplus/HostLib/RegisterFilterLibHost/RegisterFilterLibHost.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  ToolChainHarnessLib|HBFAplus/Infrastructure/ToolChainHarnessLib/ToolChainHarnessLib.inf
  HostDispatcherLib|HBFAplus/HostLib/HostDispatcherLib/HostDispatcherLib.inf

  #---------------------------------------------------------------------------
  # EDK2 libraries usable as-is on the host (pure software, no hardware deps)
  #---------------------------------------------------------------------------
  FrameBufferBltLib|MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.inf

  #---------------------------------------------------------------------------
  # Mock Protocol Libraries (shared - installed on gFuzzHandle by constructors)
  #
  # These mirror the EDK2 directory where the real protocol is produced.
  # Each provides a mock implementation of a single UEFI protocol GUID.
  #---------------------------------------------------------------------------

  ## Mock EFI_SIMPLE_NETWORK_PROTOCOL (produced by NetworkPkg/SnpDxe)
  ## Self-contained mock — direct protocol implementation with fuzz-driven Receive
  MockgEfiSimpleNetworkProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf

  ## Mock EFI_MANAGED_NETWORK_PROTOCOL (produced by NetworkPkg/MnpDxe)
  ## Self-contained mock — fuzz-driven Receive with deferred callback pattern
  MockgEfiManagedNetworkProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkProtocolGuid/MockgEfiManagedNetworkProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiManagedNetworkServiceBindingProtocolGuid (produced by NetworkPkg/MnpDxe)
  MockgEfiManagedNetworkServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkServiceBindingProtocolGuid/MockgEfiManagedNetworkServiceBindingProtocolGuid.inf

  ## Mock EFI_IP6_CONFIG_PROTOCOL (produced by NetworkPkg/Ip6Dxe)
  MockgEfiIp6ConfigProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf

  ## Mock EFI_RNG_PROTOCOL (produced by SecurityPkg/RandomNumberGenerator/RngDxe)
  MockgEfiRngProtocolGuid|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf

  ## Mock EFI_UDP6_PROTOCOL (produced by NetworkPkg/Udp6Dxe)
  MockgEfiUdp6ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ProtocolGuid/MockgEfiUdp6ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiUdp6ServiceBindingProtocolGuid (produced by NetworkPkg/Udp6Dxe)
  MockgEfiUdp6ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ServiceBindingProtocolGuid/MockgEfiUdp6ServiceBindingProtocolGuid.inf

  ## Mock PciBusDxe — all protocols produced by MdeModulePkg/Bus/Pci/PciBusDxe
  ## (gEfiPciIoProtocolGuid, gEfiDevicePathProtocolGuid,
  ##  gEfiBusSpecificDriverOverrideProtocolGuid, gEfiPciHotPlugRequestProtocolGuid,
  ##  gEfiLoadFile2ProtocolGuid)
  MockgEfiPciIoProtocolGuid|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf

  ## Mock USB2 Host Controller — EFI_USB2_HC_PROTOCOL (consumed by UsbBusDxe)
  MockgEfiUsb2HcProtocolGuid|HBFAplus/MockProtocols/MdeModulePkg/Bus/Usb/UsbBusDxe/MockgEfiUsb2HcProtocolGuid/MockgEfiUsb2HcProtocolGuid.inf

  ## Mock Block I/O — EFI_BLOCK_IO_PROTOCOL (consumed by DiskIoDxe, PartitionDxe)
  MockgEfiBlockIoProtocolGuid|HBFAplus/MockProtocols/MdeModulePkg/Universal/Disk/DiskIoDxe/MockgEfiBlockIoProtocolGuid/MockgEfiBlockIoProtocolGuid.inf

  ## Mock EFI_DPC_PROTOCOL (produced by NetworkPkg/DpcDxe)
  MockgEfiDpcProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf

  ## Mock EFI_SMM_BASE2_PROTOCOL (produced by PI SMM Core, consumed by SmmServicesTableLib)
  MockgEfiSmmBase2ProtocolGuid|HBFAplus/MockProtocols/MdePkg/SmmServicesTableLib/MockgEfiSmmBase2ProtocolGuid/MockgEfiSmmBase2ProtocolGuid.inf

  ## Mock EFI_SMM_COMMUNICATION_PROTOCOL (DXE→SMM bridge via gSmst->SmiManage)
  MockgEfiSmmCommunicationProtocolGuid|HBFAplus/MockProtocols/MdeModulePkg/SmmCommunication/MockgEfiSmmCommunicationProtocolGuid/MockgEfiSmmCommunicationProtocolGuid.inf

  ## Mock MNP — self-contained separate protocol + service-binding mocks

  ## Mock EFI_IP6_PROTOCOL (produced by NetworkPkg/Ip6Dxe)
  MockgEfiIp6ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiIp6ServiceBindingProtocolGuid (produced by NetworkPkg/Ip6Dxe)
  MockgEfiIp6ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf

  ## Mock EFI_TCP6_PROTOCOL (produced by NetworkPkg/TcpDxe)
  MockgEfiTcp6ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp6ProtocolGuid/MockgEfiTcp6ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiTcp6ServiceBindingProtocolGuid (produced by NetworkPkg/TcpDxe)
  MockgEfiTcp6ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp6ServiceBindingProtocolGuid/MockgEfiTcp6ServiceBindingProtocolGuid.inf

  ## Mock EFI_IP4_PROTOCOL (produced by NetworkPkg/Ip4Dxe)
  MockgEfiIp4ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ProtocolGuid/MockgEfiIp4ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiIp4ServiceBindingProtocolGuid (produced by NetworkPkg/Ip4Dxe)
  MockgEfiIp4ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ServiceBindingProtocolGuid/MockgEfiIp4ServiceBindingProtocolGuid.inf

  ## Mock EFI_IP4_CONFIG2_PROTOCOL (produced by NetworkPkg/Ip4Dxe)
  MockgEfiIp4Config2ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4Config2ProtocolGuid/MockgEfiIp4Config2ProtocolGuid.inf

  ## Mock EFI_UDP4_PROTOCOL (produced by NetworkPkg/Udp4Dxe)
  MockgEfiUdp4ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Udp4Dxe/MockgEfiUdp4ProtocolGuid/MockgEfiUdp4ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiUdp4ServiceBindingProtocolGuid (produced by NetworkPkg/Udp4Dxe)
  MockgEfiUdp4ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Udp4Dxe/MockgEfiUdp4ServiceBindingProtocolGuid/MockgEfiUdp4ServiceBindingProtocolGuid.inf

  ## Mock EFI_ARP_PROTOCOL (produced by NetworkPkg/ArpDxe)
  MockgEfiArpProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpProtocolGuid/MockgEfiArpProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiArpServiceBindingProtocolGuid (produced by NetworkPkg/ArpDxe)
  MockgEfiArpServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpServiceBindingProtocolGuid/MockgEfiArpServiceBindingProtocolGuid.inf

  ## Mock EFI_TCP4_PROTOCOL (produced by NetworkPkg/TcpDxe)
  MockgEfiTcp4ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp4ProtocolGuid/MockgEfiTcp4ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiTcp4ServiceBindingProtocolGuid (produced by NetworkPkg/TcpDxe)
  MockgEfiTcp4ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp4ServiceBindingProtocolGuid/MockgEfiTcp4ServiceBindingProtocolGuid.inf

  ## Mock EFI_TLS_PROTOCOL (produced by NetworkPkg/TlsDxe)
  MockgEfiTlsProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsProtocolGuid/MockgEfiTlsProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiTlsServiceBindingProtocolGuid (produced by NetworkPkg/TlsDxe)
  MockgEfiTlsServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsServiceBindingProtocolGuid/MockgEfiTlsServiceBindingProtocolGuid.inf

  ## Mock EFI_TLS_CONFIGURATION_PROTOCOL (produced by NetworkPkg/TlsDxe)
  MockgEfiTlsConfigurationProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsConfigurationProtocolGuid/MockgEfiTlsConfigurationProtocolGuid.inf

  ## Mock EFI_HTTP_UTILITIES_PROTOCOL (produced by NetworkPkg/HttpUtilitiesDxe)
  MockgEfiHttpUtilitiesProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/HttpUtilitiesDxe/MockgEfiHttpUtilitiesProtocolGuid/MockgEfiHttpUtilitiesProtocolGuid.inf

  ## Mock EFI_HTTP_PROTOCOL (produced by NetworkPkg/HttpDxe)
  MockgEfiHttpProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/HttpDxe/MockgEfiHttpProtocolGuid/MockgEfiHttpProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiHttpServiceBindingProtocolGuid (produced by NetworkPkg/HttpDxe)
  MockgEfiHttpServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/HttpDxe/MockgEfiHttpServiceBindingProtocolGuid/MockgEfiHttpServiceBindingProtocolGuid.inf

  ## ----------  Phase 3: DHCP + DNS + MTFTP (PXE boot path) ----------

  ## Mock EFI_DHCP4_PROTOCOL (produced by NetworkPkg/Dhcp4Dxe)
  MockgEfiDhcp4ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ProtocolGuid/MockgEfiDhcp4ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiDhcp4ServiceBindingProtocolGuid
  MockgEfiDhcp4ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ServiceBindingProtocolGuid/MockgEfiDhcp4ServiceBindingProtocolGuid.inf

  ## Mock EFI_DHCP6_PROTOCOL (produced by NetworkPkg/Dhcp6Dxe)
  MockgEfiDhcp6ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Dhcp6Dxe/MockgEfiDhcp6ProtocolGuid/MockgEfiDhcp6ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiDhcp6ServiceBindingProtocolGuid
  MockgEfiDhcp6ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Dhcp6Dxe/MockgEfiDhcp6ServiceBindingProtocolGuid/MockgEfiDhcp6ServiceBindingProtocolGuid.inf

  ## Mock EFI_DNS4_PROTOCOL (produced by NetworkPkg/DnsDxe)
  MockgEfiDns4ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns4ProtocolGuid/MockgEfiDns4ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiDns4ServiceBindingProtocolGuid
  MockgEfiDns4ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns4ServiceBindingProtocolGuid/MockgEfiDns4ServiceBindingProtocolGuid.inf

  ## Mock EFI_DNS6_PROTOCOL (produced by NetworkPkg/DnsDxe)
  MockgEfiDns6ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ProtocolGuid/MockgEfiDns6ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiDns6ServiceBindingProtocolGuid
  MockgEfiDns6ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ServiceBindingProtocolGuid/MockgEfiDns6ServiceBindingProtocolGuid.inf

  ## Mock EFI_MTFTP4_PROTOCOL (produced by NetworkPkg/Mtftp4Dxe)
  MockgEfiMtftp4ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Mtftp4Dxe/MockgEfiMtftp4ProtocolGuid/MockgEfiMtftp4ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiMtftp4ServiceBindingProtocolGuid
  MockgEfiMtftp4ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Mtftp4Dxe/MockgEfiMtftp4ServiceBindingProtocolGuid/MockgEfiMtftp4ServiceBindingProtocolGuid.inf

  ## Mock EFI_MTFTP6_PROTOCOL (produced by NetworkPkg/Mtftp6Dxe)
  MockgEfiMtftp6ProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Mtftp6Dxe/MockgEfiMtftp6ProtocolGuid/MockgEfiMtftp6ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiMtftp6ServiceBindingProtocolGuid
  MockgEfiMtftp6ServiceBindingProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/Mtftp6Dxe/MockgEfiMtftp6ServiceBindingProtocolGuid/MockgEfiMtftp6ServiceBindingProtocolGuid.inf

  ## Mock HII Database / String / ConfigRouting protocols (produced by MdeModulePkg/Universal/HiiDatabaseDxe)
  MockHiiDatabaseProtocol|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf

  ## Mock EFI_NETWORK_INTERFACE_IDENTIFIER_PROTOCOL (revision 0x31, data-only)
  MockgEfiNetworkInterfaceIdentifierProtocolGuid_31|HBFAplus/MockProtocols/MdePkg/NetworkInterfaceIdentifierDxe/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31.inf

  ## Mock EFI_ACPI_TABLE_PROTOCOL (function-pointer, InstallAcpiTable/UninstallAcpiTable)
  MockgEfiAcpiTableProtocolGuid|HBFAplus/MockProtocols/MdePkg/AcpiTableDxe/MockgEfiAcpiTableProtocolGuid/MockgEfiAcpiTableProtocolGuid.inf

  ## Mock EFI_ADAPTER_INFORMATION_PROTOCOL (function-pointer, GetInfo/SetInfo/GetSupportedTypes)
  MockgEfiAdapterInformationProtocolGuid|HBFAplus/MockProtocols/MdePkg/AdapterInformationDxe/MockgEfiAdapterInformationProtocolGuid/MockgEfiAdapterInformationProtocolGuid.inf

  ## Mock EFI_AUTHENTICATION_INFO_PROTOCOL (function-pointer, Get/Set)
  MockgEfiAuthenticationInfoProtocolGuid|HBFAplus/MockProtocols/MdePkg/AuthenticationInfoDxe/MockgEfiAuthenticationInfoProtocolGuid/MockgEfiAuthenticationInfoProtocolGuid.inf

  ## Mock EDKII_HTTP_CALLBACK_PROTOCOL (function-pointer, Callback)
  MockgEdkiiHttpCallbackProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/HttpDxe/MockgEdkiiHttpCallbackProtocolGuid/MockgEdkiiHttpCallbackProtocolGuid.inf

  ## Mock EFI_HII_CONFIG_ACCESS_PROTOCOL (function-pointer, ExtractConfig/RouteConfig/Callback)
  MockgEfiHiiConfigAccessProtocolGuid|HBFAplus/MockProtocols/MdePkg/HiiConfigAccessDxe/MockgEfiHiiConfigAccessProtocolGuid/MockgEfiHiiConfigAccessProtocolGuid.inf

  ## Mock EFI_HII_CONFIG_ROUTING_PROTOCOL (function-pointer, 6 functions)
  MockgEfiHiiConfigRoutingProtocolGuid|HBFAplus/MockProtocols/MdePkg/HiiConfigRoutingDxe/MockgEfiHiiConfigRoutingProtocolGuid/MockgEfiHiiConfigRoutingProtocolGuid.inf

  ## Mock EFI_HII_POPUP_PROTOCOL (function-pointer + Revision, CreatePopup)
  MockgEfiHiiPopupProtocolGuid|HBFAplus/MockProtocols/MdePkg/HiiPopupDxe/MockgEfiHiiPopupProtocolGuid/MockgEfiHiiPopupProtocolGuid.inf

  ## Mock EFI_ISCSI_INITIATOR_NAME_PROTOCOL (function-pointer, Get/Set)
  MockgEfiIScsiInitiatorNameProtocolGuid|HBFAplus/MockProtocols/MdePkg/IScsiInitiatorNameDxe/MockgEfiIScsiInitiatorNameProtocolGuid/MockgEfiIScsiInitiatorNameProtocolGuid.inf

  ## Mock EFI_IPSEC2_PROTOCOL (function-pointer + data, ProcessExt/DisabledFlag)
  MockgEfiIpSec2ProtocolGuid|HBFAplus/MockProtocols/MdePkg/IpSecDxe/MockgEfiIpSec2ProtocolGuid/MockgEfiIpSec2ProtocolGuid.inf

  ## Mock EFI_RAM_DISK_PROTOCOL (function-pointer, Register/Unregister)
  MockgEfiRamDiskProtocolGuid|HBFAplus/MockProtocols/MdePkg/RamDiskDxe/MockgEfiRamDiskProtocolGuid/MockgEfiRamDiskProtocolGuid.inf

  ## Mock EFI_SUPPLICANT_PROTOCOL (function-pointer, BuildResp/Process/Set/GetData)
  MockgEfiSupplicantProtocolGuid|HBFAplus/MockProtocols/MdePkg/SupplicantDxe/MockgEfiSupplicantProtocolGuid/MockgEfiSupplicantProtocolGuid.inf

  ## Mock EFI_VLAN_CONFIG_PROTOCOL (function-pointer, Set/Find/Remove)
  MockgEfiVlanConfigProtocolGuid|HBFAplus/MockProtocols/MdePkg/VlanConfigDxe/MockgEfiVlanConfigProtocolGuid/MockgEfiVlanConfigProtocolGuid.inf

  ## Mock EFI_WIRELESS_MAC_CONNECTION_II_PROTOCOL (WiFi2, GetNetworks/Connect/Disconnect)
  MockgEfiWiFi2ProtocolGuid|HBFAplus/MockProtocols/MdePkg/WiFi2Dxe/MockgEfiWiFi2ProtocolGuid/MockgEfiWiFi2ProtocolGuid.inf

  ## Mock EFI_EAP_CONFIGURATION_PROTOCOL (SetData/GetData, fuzz-aware store)
  MockgEfiEapConfigurationProtocolGuid|HBFAplus/MockProtocols/MdePkg/EapConfigurationDxe/MockgEfiEapConfigurationProtocolGuid/MockgEfiEapConfigurationProtocolGuid.inf

  ## Mock EDKII_WIFI_PROFILE_SYNC_PROTOCOL (GetProfile/SetConnectState/GetConnectState)
  MockgEdkiiWiFiProfileSyncProtocolGuid|HBFAplus/MockProtocols/NetworkPkg/WifiConnectionManagerDxe/MockgEdkiiWiFiProfileSyncProtocolGuid/MockgEdkiiWiFiProfileSyncProtocolGuid.inf

  ## Mock EFI_HASH2_PROTOCOL (GetHashSize/Hash/HashInit/HashUpdate/HashFinal)
  MockgEfiHash2ProtocolGuid|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ProtocolGuid/MockgEfiHash2ProtocolGuid.inf

  ## Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiHash2ServiceBindingProtocolGuid
  MockgEfiHash2ServiceBindingProtocolGuid|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ServiceBindingProtocolGuid/MockgEfiHash2ServiceBindingProtocolGuid.inf

  ## Mock EFI_EXT_SCSI_PASS_THRU_PROTOCOL (PassThru/GetNextTargetLun/BuildDevicePath)
  MockgEfiExtScsiPassThruProtocolGuid|HBFAplus/MockProtocols/MdePkg/ExtScsiPassThruDxe/MockgEfiExtScsiPassThruProtocolGuid/MockgEfiExtScsiPassThruProtocolGuid.inf

  ## Mock EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL (Read/Write/EraseBlocks)
  MockgEfiFirmwareVolumeBlockProtocolGuid|HBFAplus/MockProtocols/OvmfPkg/EmuVariableFvbRuntimeDxe/MockgEfiFirmwareVolumeBlockProtocolGuid/MockgEfiFirmwareVolumeBlockProtocolGuid.inf



  ## Mock EFI_HTTP_BOOT_CALLBACK_PROTOCOL (Callback)
  MockgEfiHttpBootCallbackProtocolGuid|HBFAplus/MockProtocols/MdePkg/HttpBootCallbackDxe/MockgEfiHttpBootCallbackProtocolGuid/MockgEfiHttpBootCallbackProtocolGuid.inf

  ## Mock EFI_S3_SAVE_STATE_PROTOCOL (Write/Insert/Label/Compare)
  MockgEfiS3SaveStateProtocolGuid|HBFAplus/MockProtocols/MdePkg/S3SaveStateDxe/MockgEfiS3SaveStateProtocolGuid/MockgEfiS3SaveStateProtocolGuid.inf

  ## Mock EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL (Mem/Io/Pci R/W, Map, DMA)
  MockgEfiPciRootBridgeIoProtocolGuid|HBFAplus/MockProtocols/MdePkg/PciRootBridgeIoDxe/MockgEfiPciRootBridgeIoProtocolGuid/MockgEfiPciRootBridgeIoProtocolGuid.inf

  #---------------------------------------------------------------------------
  # Real EDK2 Libraries (actual code under test or required dependencies)
  #---------------------------------------------------------------------------
  PrintLib|HBFAplus/HostLib/PrintLibHost/PrintLibHost.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  SafeIntLib|MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
  PeCoffLib|MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
  PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
  PeCoffExtraActionLib|MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
  PeCoffExtraActionLib|MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
  SortLib|MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
  HttpLib|NetworkPkg/Library/DxeHttpLib/DxeHttpLib.inf
  NetLib|NetworkPkg/Library/DxeNetLib/DxeNetLib.inf
  UdpIoLib|NetworkPkg/Library/DxeUdpIoLib/DxeUdpIoLib.inf
  IpIoLib|NetworkPkg/Library/DxeIpIoLib/DxeIpIoLib.inf
  DpcLib|NetworkPkg/Library/DxeDpcLib/DxeDpcLib.inf


  #---------------------------------------------------------------------------
  # Null/Stub Libraries
  #---------------------------------------------------------------------------
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  ReportStatusCodeLib|MdePkg/Library/BaseReportStatusCodeLibNull/BaseReportStatusCodeLibNull.inf
  UefiHiiServicesLib|MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
  HiiLib|HBFAplus/HostLib/UefiHiiLibHost/UefiHiiLibHost.inf
  VariablePolicyLib|MdeModulePkg/Library/VariablePolicyLib/VariablePolicyLib.inf
  VariablePolicyHelperLib|MdeModulePkg/Library/VariablePolicyHelperLib/VariablePolicyHelperLib.inf

[PcdsFixedAtBuild]
  #
  # Debug output control.  DebugLibHost ignores these PCDs (it hard-codes
  # everything enabled), but they are set here for two reasons:
  #   1. edk2 libraries that check PCDs directly (not via DebugLib API)
  #      will see the correct values.
  #   2. Documentation: makes the intended debug policy explicit.
  #
  # DEBUG_PROPERTY_DEBUG_ASSERT_ENABLED  = 0x01
  # DEBUG_PROPERTY_DEBUG_PRINT_ENABLED   = 0x02
  # DEBUG_PROPERTY_DEBUG_CODE_ENABLED    = 0x04
  # DEBUG_PROPERTY_CLEAR_MEMORY_ENABLED  = 0x08
  # DEBUG_PROPERTY_ASSERT_BREAKPOINT_ENABLED = 0x10
  #
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x2F

  #
  # Print-error-level bitmask — controls which DEBUG() levels are active.
  # 0x80000040 = DEBUG_ERROR | DEBUG_INFO  (default)
  # 0x80400044 = DEBUG_ERROR | DEBUG_WARN | DEBUG_INFO | DEBUG_VERBOSE
  # 0xFFFFFFFF = everything
  #
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0xFFFFFFFF

  #
  # Force DUID-LLT type for DHCPv6 Client Identifier.
  # Default is 4 (UUID) which uses system SMBIOS GUID — non-deterministic
  # in host fuzzing.  Type 1 (LLT) uses GetTime + MAC address, both of
  # which are deterministic in our mock environment (fixed Time.c +
  # MockSNP MAC 02:00:00:00:00:01), enabling pre-computed seed packets.
  #
  gEfiNetworkPkgTokenSpaceGuid.PcdDhcp6UidType|0x1

[PcdsPatchableInModule]
  #
  # Variable / FaultTolerantWrite NV-storage base PCDs.  Declared platform-wide
  # so that VariableSmm and TestEmuVariableFvbDriver agree on the access method
  # (PatchableInModule).  All zero — the EmuVariableNvMode path takes over.
  #
  gEfiMdeModulePkgTokenSpaceGuid.PcdFlashNvStorageVariableBase64|0x0
  gEfiMdeModulePkgTokenSpaceGuid.PcdFlashNvStorageFtwWorkingBase64|0x0
  gEfiMdeModulePkgTokenSpaceGuid.PcdFlashNvStorageFtwSpareBase64|0x0
  gEfiMdeModulePkgTokenSpaceGuid.PcdEmuVariableNvStoreReserved|0x0

#=============================================================================
# Components - Fuzz Harnesses
#=============================================================================
#
# Each harness uses the real driver's DriverBinding/ServiceBinding flow.
# Mock protocols are installed on gFuzzHandle by shared mock library constructors.
#
# The NULL|<driver>.inf pattern links real driver code into the harness.
#=============================================================================

[Components]
  HBFAplus/FuzzHarness/SecurityPkg/DxeTpmMeasureBootLib_LLMGenerated/TestDxeTpmMeasureBootLib/TestDxeTpmMeasureBootLib.inf






































































































































  #---------------------------------------------------------------------------
  # Dhcp6Dxe - Full driver flow (DriverBinding → ServiceBinding → CreateChild)
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Dhcp6Dxe/TestDhcp6Driver/TestDhcp6Driver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Dhcp6Dxe/Dhcp6Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ProtocolGuid/MockgEfiUdp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ServiceBindingProtocolGuid/MockgEfiUdp6ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/Dhcp6Dxe
  }

  #---------------------------------------------------------------------------
  # TcpDxe (unified TCP4+TCP6) — single harness for the single TcpDxe driver.
  #
  # TCP4: 10 protocol functions + DriverBinding + ServiceBinding (15 API selectors)
  # TCP6:  9 protocol functions + DriverBinding + ServiceBinding (14 API selectors)
  # NOTE: TCP6 has NO Routes() API (unlike TCP4).
  # Consumed protocols: IP4/IP4SB, IP6/IP6SB, Hash2/Hash2SB, DevicePath, DPC, RNG.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/TcpDxe/TestTcpDriver/TestTcpDriver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/TcpDxe/TcpDxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ProtocolGuid/MockgEfiIp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ServiceBindingProtocolGuid/MockgEfiIp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ProtocolGuid/MockgEfiHash2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ServiceBindingProtocolGuid/MockgEfiHash2ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/TcpDxe
      GCC:*_*_*_DLINK_FLAGS = -Wl,--wrap=TcpChecksum
  }

  #---------------------------------------------------------------------------
  # TcpDxe L1L2 Deep — real Ip4Dxe + Ip6Dxe → real TcpDxe, MNP/ARP mocked
  #
  # Mock boundary: MNP + ARP (gEfiManagedNetworkProtocolGuid)
  # BUG CLASS: IP4/IP6↔TCP interaction bugs invisible to shallow harness.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/TcpDxe/TestTcpDriverL1L2Deep/TestTcpDriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|NetworkPkg/Ip6Dxe/Ip6Dxe.inf
      NULL|NetworkPkg/TcpDxe/TcpDxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkProtocolGuid/MockgEfiManagedNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkServiceBindingProtocolGuid/MockgEfiManagedNetworkServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpProtocolGuid/MockgEfiArpProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpServiceBindingProtocolGuid/MockgEfiArpServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ProtocolGuid/MockgEfiHash2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ServiceBindingProtocolGuid/MockgEfiHash2ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/TcpDxe -I$(WORKSPACE)/edk2/NetworkPkg/Ip4Dxe -I$(WORKSPACE)/edk2/NetworkPkg/Ip6Dxe
      GCC:*_*_*_DLINK_FLAGS = -Wl,--wrap=TcpChecksum -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # TcpDxe Deep — full dual-stack: MnpDxe → ArpDxe → Ip4Dxe + Ip6Dxe → TcpDxe
  #
  # Mock boundary: SNP (gEfiSimpleNetworkProtocolGuid)
  # BUG CLASS: Cross-layer interaction bugs across entire IPv4+IPv6+TCP stack.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/TcpDxe/TestTcpDriverDeep/TestTcpDriverDeep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/ArpDxe/ArpDxe.inf
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|NetworkPkg/Ip6Dxe/Ip6Dxe.inf
      NULL|NetworkPkg/TcpDxe/TcpDxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ProtocolGuid/MockgEfiHash2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ServiceBindingProtocolGuid/MockgEfiHash2ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/TcpDxe -I$(WORKSPACE)/edk2/NetworkPkg/Ip4Dxe -I$(WORKSPACE)/edk2/NetworkPkg/Ip6Dxe -I$(WORKSPACE)/edk2/NetworkPkg/MnpDxe -I$(WORKSPACE)/edk2/NetworkPkg/ArpDxe
      GCC:*_*_*_DLINK_FLAGS = -Wl,--wrap=TcpChecksum -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Udp4Dxe - Full driver flow (DriverBinding → ServiceBinding → CreateChild)
  #
  # UDP4 protocol driver: provides connectionless datagram transport over IPv4.
  # Primary fuzz targets: all 8 EFI_UDP4_PROTOCOL APIs + ServiceBinding lifecycle.
  # Consumed protocols: IP4/IP4SB, DPC, RNG (for PseudoRandomU32 in entry point).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Udp4Dxe/TestUdp4Driver/TestUdp4Driver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ProtocolGuid/MockgEfiIp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ServiceBindingProtocolGuid/MockgEfiIp4ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/Udp4Dxe
  }

  #---------------------------------------------------------------------------
  # Udp4Dxe L1L2 Deep — real Ip4Dxe → real Udp4Dxe, MNP/ARP mocked
  #
  # Mock boundary: MNP + ARP (gEfiManagedNetworkProtocolGuid)
  # BUG CLASS: IP4↔UDP4 interaction bugs invisible to shallow harness.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Udp4Dxe/TestUdp4DriverL1L2Deep/TestUdp4DriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkProtocolGuid/MockgEfiManagedNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkServiceBindingProtocolGuid/MockgEfiManagedNetworkServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpProtocolGuid/MockgEfiArpProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpServiceBindingProtocolGuid/MockgEfiArpServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Udp4Dxe Deep — full IPv4 stack: MnpDxe → ArpDxe → Ip4Dxe → Udp4Dxe
  #
  # Mock boundary: SNP (gEfiSimpleNetworkProtocolGuid)
  # BUG CLASS: Cross-layer interaction bugs across the entire IPv4 stack.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Udp4Dxe/TestUdp4DriverDeep/TestUdp4DriverDeep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/ArpDxe/ArpDxe.inf
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Udp6Dxe - Full driver flow (DriverBinding → ServiceBinding → CreateChild)
  #
  # UDP6 protocol driver: provides connectionless datagram transport over IPv6.
  # Primary fuzz targets: all 7 EFI_UDP6_PROTOCOL APIs + ServiceBinding lifecycle.
  # Consumed protocols: IP6/IP6SB, DPC, RNG (for PseudoRandomU32 in entry point).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Udp6Dxe/TestUdp6Driver/TestUdp6Driver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Udp6Dxe/Udp6Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/Udp6Dxe
  }

  #---------------------------------------------------------------------------
  # Udp6Dxe L1L2 Deep — real Ip6Dxe + Udp6Dxe, MNP layer mocked.
  #
  # Mock boundary: MNP (gEfiManagedNetworkProtocolGuid)
  # BUG CLASS: Cross-layer interaction bugs between IP6 and UDP6.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Udp6Dxe/TestUdp6DriverL1L2Deep/TestUdp6DriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Ip6Dxe/Ip6Dxe.inf
      NULL|NetworkPkg/Udp6Dxe/Udp6Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkProtocolGuid/MockgEfiManagedNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkServiceBindingProtocolGuid/MockgEfiManagedNetworkServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Mtftp4Dxe - Full driver flow (DriverBinding → ServiceBinding → CreateChild)
  #
  # MTFTP4 protocol driver: provides multicast TFTP over IPv4.
  # Primary fuzz targets: all 8 EFI_MTFTP4_PROTOCOL APIs, especially
  # ParseOptions (OACK packet parser) and ReadFile/WriteFile token paths.
  # Consumed protocols: UDP4/UDP4SB (no DPC or RNG dependency).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Mtftp4Dxe/TestMtftp4Driver/TestMtftp4Driver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Mtftp4Dxe/Mtftp4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp4Dxe/MockgEfiUdp4ProtocolGuid/MockgEfiUdp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp4Dxe/MockgEfiUdp4ServiceBindingProtocolGuid/MockgEfiUdp4ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/Mtftp4Dxe
  }

  #---------------------------------------------------------------------------
  # Mtftp4Dxe Deep - Full IPv4 protocol stack (MNP→ARP→IP4→UDP4→MTFTP4)
  # with only mock SNP at the bottom for fuzz injection.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Mtftp4Dxe/TestMtftp4DriverDeep/TestMtftp4DriverDeep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/ArpDxe/ArpDxe.inf
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|NetworkPkg/Mtftp4Dxe/Mtftp4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Mtftp4Dxe L1L2 Deep - Real Udp4Dxe + Mtftp4Dxe with IP4-level mock boundary.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Mtftp4Dxe/TestMtftp4DriverL1L2Deep/TestMtftp4DriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|NetworkPkg/Mtftp4Dxe/Mtftp4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ProtocolGuid/MockgEfiIp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ServiceBindingProtocolGuid/MockgEfiIp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4Config2ProtocolGuid/MockgEfiIp4Config2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Mtftp6Dxe - Full driver flow (DriverBinding → ServiceBinding → CreateChild)
  #
  # MTFTP6 protocol driver: provides multicast TFTP over IPv6.
  # Primary fuzz targets: all 8 EFI_MTFTP6_PROTOCOL APIs, especially
  # ParseOptions (OACK packet parser) and ReadFile/WriteFile token paths.
  # Consumed protocols: UDP6/UDP6SB + DPC (via UdpIoLib).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Mtftp6Dxe/TestMtftp6Driver/TestMtftp6Driver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Mtftp6Dxe/Mtftp6Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ProtocolGuid/MockgEfiUdp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ServiceBindingProtocolGuid/MockgEfiUdp6ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/Mtftp6Dxe
  }

  #---------------------------------------------------------------------------
  # Mtftp6Dxe L1L2 Deep - Real Udp6Dxe + Mtftp6Dxe with IP6-level mock boundary.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Mtftp6Dxe/TestMtftp6DriverL1L2Deep/TestMtftp6DriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Udp6Dxe/Udp6Dxe.inf
      NULL|NetworkPkg/Mtftp6Dxe/Mtftp6Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # PE/COFF Libraries - Pure library fuzzing (no DriverBinding/ServiceBinding)
  #
  # Targets: BasePeCoffLib (GetImageInfo, LoadImage, RelocateImage)
  #          BasePeCoffGetEntryPointLib (GetEntryPoint, GetMachineType, GetPdbPointer)
  #          BasePeCoffExtraActionLibNull (ExtraAction stubs)
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdePkg/BasePeCoffLib/TestPeCoff/TestPeCoff.inf

  #---------------------------------------------------------------------------
  # BasePeCoffGetEntryPointLib - Focused library fuzzing
  #
  # Targets: PeCoffLoaderGetEntryPoint, GetMachineType, GetPdbPointer,
  #          GetSizeOfHeaders, SearchImageBase
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdePkg/BasePeCoffGetEntryPointLib/TestPeCoffGetEntryPoint/TestPeCoffGetEntryPoint.inf

  #---------------------------------------------------------------------------
  # ArpDxe - Full driver flow (DriverBinding → ServiceBinding → CreateChild)
  #
  # ARP protocol driver: resolves IPv4 → MAC addresses via RFC 826.
  # Primary fuzz target: ArpOnFrameRcvdDpc() packet parser.
  # Consumed protocols: MNP + MNP ServiceBinding (both 100% mocked).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/ArpDxe/TestArpDriver/TestArpDriver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/ArpDxe/ArpDxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkProtocolGuid/MockgEfiManagedNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkServiceBindingProtocolGuid/MockgEfiManagedNetworkServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/ArpDxe
  }

  #---------------------------------------------------------------------------
  # ArpDxe L1L2 Deep - Real MnpDxe + ArpDxe with SNP-level mock boundary.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/ArpDxe/TestArpDriverL1L2Deep/TestArpDriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/ArpDxe/ArpDxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/ArpDxe
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # MnpDxe - Managed Network Protocol driver (layer-2 abstraction over SNP).
  # Consumed protocols: SNP (SimpleNetwork) + DPC.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/MnpDxe/TestMnpDriver/TestMnpDriver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/MnpDxe
  }

  #---------------------------------------------------------------------------
  # MnpDxe L1L2 Deep - Real SnpDxe + MnpDxe with NII/PCI mock boundary.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/MnpDxe/TestMnpDriverL1L2Deep/TestMnpDriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/SnpDxe/SnpDxe.inf
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/NetworkInterfaceIdentifierDxe/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/MnpDxe
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Dhcp4Dxe - Full driver flow (DriverBinding → ServiceBinding → CreateChild)
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Dhcp4Dxe/TestDhcp4Driver/TestDhcp4Driver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Dhcp4Dxe/Dhcp4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp4Dxe/MockgEfiUdp4ProtocolGuid/MockgEfiUdp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp4Dxe/MockgEfiUdp4ServiceBindingProtocolGuid/MockgEfiUdp4ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/Dhcp4Dxe
  }

  #---------------------------------------------------------------------------
  # Dhcp4Dxe Deep - Full IPv4 protocol stack (MNP→ARP→IP4→UDP4→DHCP4)
  # with only mock SNP at the bottom for fuzz injection.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Dhcp4Dxe/TestDhcp4DriverDeep/TestDhcp4DriverDeep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/ArpDxe/ArpDxe.inf
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|NetworkPkg/Dhcp4Dxe/Dhcp4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      # These are Component Name UI helpers never called during fuzzing.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Dhcp4Dxe MMIO Deep - Full USB NIC + IPv4 stack with 11 real edk2 drivers.
  # Research harness: demonstrates MMIO-level injection ineffectiveness.
  #
  # Stack: MockPciIo+MockUsb2Hc (fuzz) → XhciDxe → UsbBusDxe → UsbRndis
  #        → NetworkCommon (UNDI) → SnpDxe → MnpDxe → ArpDxe → Ip4Dxe
  #        → Udp4Dxe → Dhcp4Dxe
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Dhcp4Dxe/TestDhcp4DriverCrDeep/TestDhcp4DriverCrDeep.inf {
    <LibraryClasses>
      UefiUsbLib|MdePkg/Library/UefiUsbLib/UefiUsbLib.inf
      # USB subsystem (real drivers)
      NULL|MdeModulePkg/Bus/Pci/XhciDxe/XhciDxe.inf
      NULL|MdeModulePkg/Bus/Usb/UsbBusDxe/UsbBusDxe.inf
      NULL|MdeModulePkg/Bus/Usb/UsbNetwork/UsbRndis/UsbRndis.inf
      NULL|MdeModulePkg/Bus/Usb/UsbNetwork/NetworkCommon/NetworkCommon.inf
      # Network protocol stack (real drivers)
      NULL|NetworkPkg/SnpDxe/SnpDxe.inf
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/ArpDxe/ArpDxe.inf
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|NetworkPkg/Dhcp4Dxe/Dhcp4Dxe.inf
      # CR mock boundary — synthetic MMIO ONLY (per Lemix-style CR definition):
      #   writes ignored, reads served from input stream, no peripheral state.
      # XhciDxe must drive itself entirely from this surface; if it fails to
      # bind, UsbBusDxe never sees a Usb2Hc producer and the stack stalls.
      # No MockUsb2Hc fallback is installed — that would violate the CR purity
      # claim made in the paper text.
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      # Infrastructure mocks
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
    <PcdsFixedAtBuild>
      gEfiNetworkPkgTokenSpaceGuid.PcdSnpCreateExitBootServicesEvent|FALSE
    <BuildOptions>
      # Multiple drivers define UpdateName() / ComponentName — allow duplication.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Bus/Pci/XhciDxe -I$(WORKSPACE)/edk2/MdeModulePkg/Bus/Usb/UsbBusDxe
  }

  #---------------------------------------------------------------------------
  # Dhcp4Dxe MAR Deep — Minimal Abstraction Rehosting (FuzzWare-style).
  #
  # Per the paper's MAR definition: model only the necessary peripheral
  # (Usb2Hc — the host controller) with structural pinning, and let every
  # higher driver run as real edk2 code.  XhciDxe is OMITTED — replaced
  # by the minimal stateful Usb2Hc model.
  #
  # Stack: MockUsb2Hc (fuzz, descriptor-pinned) → UsbBusDxe → UsbRndis
  #        → NetworkCommon (UNDI) → SnpDxe → MnpDxe → ArpDxe → Ip4Dxe
  #        → Udp4Dxe → Dhcp4Dxe   (10 real edk2 drivers above the mock)
  #
  # MockPciIo is retained because SnpDxe uses LocateDevicePath
  # (gEfiPciIoProtocolGuid) for NIC discovery — it answers discovery
  # queries only; no xHCI BAR work happens because XhciDxe is gone.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Dhcp4Dxe/TestDhcp4DriverMarDeep/TestDhcp4DriverMarDeep.inf {
    <LibraryClasses>
      UefiUsbLib|MdePkg/Library/UefiUsbLib/UefiUsbLib.inf
      # USB subsystem — XhciDxe DROPPED (replaced by minimal Usb2Hc model)
      NULL|MdeModulePkg/Bus/Usb/UsbBusDxe/UsbBusDxe.inf
      NULL|MdeModulePkg/Bus/Usb/UsbNetwork/UsbRndis/UsbRndis.inf
      NULL|MdeModulePkg/Bus/Usb/UsbNetwork/NetworkCommon/NetworkCommon.inf
      # Network protocol stack (real drivers)
      NULL|NetworkPkg/SnpDxe/SnpDxe.inf
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/ArpDxe/ArpDxe.inf
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|NetworkPkg/Dhcp4Dxe/Dhcp4Dxe.inf
      # MAR boundary — minimal Usb2Hc peripheral model
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Usb/UsbBusDxe/MockgEfiUsb2HcProtocolGuid/MockgEfiUsb2HcProtocolGuid.inf
      # PciIo retained for SnpDxe discovery (no synthetic MMIO into a real driver)
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      # Infrastructure mocks
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
    <PcdsFixedAtBuild>
      gEfiNetworkPkgTokenSpaceGuid.PcdSnpCreateExitBootServicesEvent|FALSE
    <BuildOptions>
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Bus/Usb/UsbBusDxe
  }

  #---------------------------------------------------------------------------
  # Dhcp4Dxe L1L2 Deep - Real Udp4Dxe + Dhcp4Dxe with IP4-level mock boundary.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Dhcp4Dxe/TestDhcp4DriverL1L2Deep/TestDhcp4DriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|NetworkPkg/Dhcp4Dxe/Dhcp4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ProtocolGuid/MockgEfiIp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ServiceBindingProtocolGuid/MockgEfiIp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4Config2ProtocolGuid/MockgEfiIp4Config2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Dhcp6Dxe Deep - Full IPv6 protocol stack (MNP→IP6→UDP6→DHCP6)
  # with only mock SNP at the bottom for fuzz injection.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Dhcp6Dxe/TestDhcp6DriverDeep/TestDhcp6DriverDeep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/Ip6Dxe/Ip6Dxe.inf
      NULL|NetworkPkg/Udp6Dxe/Udp6Dxe.inf
      NULL|NetworkPkg/Dhcp6Dxe/Dhcp6Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Dhcp6Dxe L1L2 Deep - Real Udp6Dxe + Dhcp6Dxe with IP6-level mock boundary.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Dhcp6Dxe/TestDhcp6DriverL1L2Deep/TestDhcp6DriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Udp6Dxe/Udp6Dxe.inf
      NULL|NetworkPkg/Dhcp6Dxe/Dhcp6Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # DnsDxe (DNS4+DNS6) - Combined driver flow mirroring edk2 single-driver
  # architecture.  Byte 0 selects DNS4 (even) vs DNS6 (odd).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/DnsDxe/TestDnsDriver/TestDnsDriver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/DnsDxe/DnsDxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp4Dxe/MockgEfiUdp4ProtocolGuid/MockgEfiUdp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp4Dxe/MockgEfiUdp4ServiceBindingProtocolGuid/MockgEfiUdp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ProtocolGuid/MockgEfiUdp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ServiceBindingProtocolGuid/MockgEfiUdp6ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/DnsDxe
  }

  #---------------------------------------------------------------------------
  # DnsDxe L1L2 Deep — real Udp4Dxe + Udp6Dxe + DnsDxe, IP4/IP6 mocked
  #
  # Mock boundary: IP4 (for DNS4 path) + IP6 (for DNS6 path)
  # BUG CLASS: UDP↔DNS interaction bugs invisible to the shallow harness.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/DnsDxe/TestDnsDriverL1L2Deep/TestDnsDriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|NetworkPkg/Udp6Dxe/Udp6Dxe.inf
      NULL|NetworkPkg/DnsDxe/DnsDxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ProtocolGuid/MockgEfiIp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ServiceBindingProtocolGuid/MockgEfiIp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4Config2ProtocolGuid/MockgEfiIp4Config2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # DnsDxe Deep — Full dual-stack: MNP→ARP→IP4→IP6→UDP4→UDP6→DNS
  # with only mock SNP at the bottom for fuzz injection.
  #
  # BUG CLASS: Cross-layer interaction bugs across the entire IPv4+IPv6
  # networking stack up through DNS resolution.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/DnsDxe/TestDnsDriverDeep/TestDnsDriverDeep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/ArpDxe/ArpDxe.inf
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|NetworkPkg/Ip6Dxe/Ip6Dxe.inf
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|NetworkPkg/Udp6Dxe/Udp6Dxe.inf
      NULL|NetworkPkg/DnsDxe/DnsDxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Ip4Dxe - Full driver flow (DriverBinding → ServiceBinding → CreateChild)
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Ip4Dxe/TestIp4Driver/TestIp4Driver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkProtocolGuid/MockgEfiManagedNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkServiceBindingProtocolGuid/MockgEfiManagedNetworkServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpProtocolGuid/MockgEfiArpProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpServiceBindingProtocolGuid/MockgEfiArpServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ProtocolGuid/MockgEfiDhcp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ServiceBindingProtocolGuid/MockgEfiDhcp4ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/Ip4Dxe
  }

  #---------------------------------------------------------------------------
  # Ip4Dxe L1L2 Deep — real MnpDxe → ArpDxe → Ip4Dxe, SNP mocked
  #
  # Mock boundary: SNP (gEfiSimpleNetworkProtocolGuid)
  # BUG CLASS: MNP↔ARP↔IP4 interaction bugs invisible to the shallow harness.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Ip4Dxe/TestIp4DriverL1L2Deep/TestIp4DriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/ArpDxe/ArpDxe.inf
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ProtocolGuid/MockgEfiDhcp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ServiceBindingProtocolGuid/MockgEfiDhcp4ServiceBindingProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Ip4Dxe Deep — full stack: MnpDxe → ArpDxe → Ip4Dxe, SNP mocked
  #
  # Note: For Ip4Dxe, deep and L1L2-deep are identical (both mock SNP, run
  # 3 real drivers) because Ip4Dxe's deps sit directly above SNP.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Ip4Dxe/TestIp4DriverDeep/TestIp4DriverDeep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/ArpDxe/ArpDxe.inf
      NULL|NetworkPkg/Ip4Dxe/Ip4Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ProtocolGuid/MockgEfiDhcp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ServiceBindingProtocolGuid/MockgEfiDhcp4ServiceBindingProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Ip6Dxe - Full driver flow (DriverBinding → ServiceBinding → CreateChild)
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Ip6Dxe/TestIp6Driver/TestIp6Driver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Ip6Dxe/Ip6Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkProtocolGuid/MockgEfiManagedNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/MnpDxe/MockgEfiManagedNetworkServiceBindingProtocolGuid/MockgEfiManagedNetworkServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/Ip6Dxe
  }

  #---------------------------------------------------------------------------
  # Ip6Dxe L1L2 Deep - Real MnpDxe + Ip6Dxe with SNP-level mock boundary.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Ip6Dxe/TestIp6DriverL1L2Deep/TestIp6DriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/Ip6Dxe/Ip6Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # Ip6Dxe Deep - Full IPv6 stack (MNP→IP6) with SNP mock boundary.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/Ip6Dxe/TestIp6DriverDeep/TestIp6DriverDeep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/MnpDxe/MnpDxe.inf
      NULL|NetworkPkg/Ip6Dxe/Ip6Dxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      # Multiple NetworkPkg drivers define UpdateName() in ComponentName.c.
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # HttpUtilitiesDxe - Simple protocol install (no DriverBinding/ServiceBinding).
  #
  # HTTP Utilities protocol: header Build/Parse operations.
  # Primary fuzz targets: HttpUtilitiesBuild, HttpUtilitiesParse.
  # Consumed protocols: NONE — fully self-contained.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/HttpUtilitiesDxe/TestHttpUtilitiesDriver/TestHttpUtilitiesDriver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/HttpUtilitiesDxe/HttpUtilitiesDxe.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/HttpUtilitiesDxe
  }

  #---------------------------------------------------------------------------
  # HiiDatabaseDxe - HII Database, String, Font, ConfigRouting, KeywordHandler.
  # L1 harness: no mock dependencies — self-contained singleton service driver.
  # Consumed protocols: NONE.
  # Produced/exercised protocols: HiiDatabase, HiiString, HiiFont,
  #   ConfigRouting, ConfigKeywordHandler.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Universal/HiiDatabaseDxe/TestHiiDatabaseDriver/TestHiiDatabaseDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/HiiDatabaseDxe
  }

  #---------------------------------------------------------------------------
  # PrintDxe - Print2/Print2S protocol (format string parsing).
  # L1 harness: no mock dependencies — self-contained singleton service driver.
  # Consumed protocols: NONE.
  # Produced/exercised protocols: EFI_PRINT2S_PROTOCOL
  #   (UnicodeBSPrint, UnicodeSPrint, AsciiBSPrint, AsciiSPrint,
  #    UnicodeValueToStringS, AsciiValueToStringS, etc.).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Universal/PrintDxe/TestPrintDxeDriver/TestPrintDxeDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/PrintDxe/PrintDxe.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/PrintDxe
  }

  #---------------------------------------------------------------------------
  # RestJsonStructureDxe - REST JSON to C structure converter protocol.
  # L1 harness: no mock dependencies — self-contained singleton service driver.
  # Consumed protocols: NONE.
  # Produced/exercised protocols: EFI_REST_JSON_STRUCTURE_PROTOCOL
  #   (Register, ToStructure, ToJson, DestoryStructure).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/RedfishPkg/RestJsonStructureDxe/TestRestJsonStructureDriver/TestRestJsonStructureDriver.inf {
    <LibraryClasses>
      NULL|RedfishPkg/RestJsonStructureDxe/RestJsonStructureDxe.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/RedfishPkg/RestJsonStructureDxe
  }

  #---------------------------------------------------------------------------
  # EnglishDxe - Unicode Collation Protocol (English).
  # L1 harness: no mock dependencies — self-contained singleton driver.
  # Consumed protocols: NONE.
  # Produced/exercised protocols: EFI_UNICODE_COLLATION2_PROTOCOL
  #   (StriColl, MetaiMatch, StrLwr, StrUpr, FatToStr, StrToFat).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/TestUnicodeCollationDriver/TestUnicodeCollationDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/EnglishDxe.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe
  }

  #---------------------------------------------------------------------------
  # UsbBusDxe - USB bus driver (enumerates USB devices via USB2 HC mock).
  # L1 harness: mocked USB2_HC_PROTOCOL, real UsbBusDxe enumeration.
  # Consumed protocols: USB2_HC (mock), DevicePath (mock).
  # Produced protocols: USB_IO (exercised by harness).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Bus/Usb/UsbBusDxe/TestUsbBusDriver/TestUsbBusDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Bus/Usb/UsbBusDxe/UsbBusDxe.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Usb/UsbBusDxe/MockgEfiUsb2HcProtocolGuid/MockgEfiUsb2HcProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Bus/Usb/UsbBusDxe
  }

  #---------------------------------------------------------------------------
  # UsbBusDxe L1L2 Deep — real XhciDxe → real UsbBusDxe, PCI_IO mocked
  #
  # Mock boundary: PCI_IO (gEfiPciIoProtocolGuid)
  # BUG CLASS: XHCI↔UsbBus interaction bugs invisible to shallow harness.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Bus/Usb/UsbBusDxe/TestUsbBusDriverL1L2Deep/TestUsbBusDriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Bus/Pci/XhciDxe/XhciDxe.inf
      NULL|MdeModulePkg/Bus/Usb/UsbBusDxe/UsbBusDxe.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Bus/Usb/UsbBusDxe -I$(WORKSPACE)/edk2/MdeModulePkg/Bus/Pci/XhciDxe
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # XhciDxe - XHCI USB 3.0 host controller driver.
  # L1 harness: mocked PCI I/O, real XhciDxe (register parsing, URB scheduling).
  # Consumed protocols: PCI_IO (mock), DevicePath (mock).
  # Produced protocols: USB2_HC (exercised by harness).
  #---------------------------------------------------------------------------
#   HBFAplus/FuzzHarness/MdeModulePkg/Bus/Pci/XhciDxe/TestXhciDriver/TestXhciDriver.inf {
#     <LibraryClasses>
#       NULL|MdeModulePkg/Bus/Pci/XhciDxe/XhciDxe.inf
#       NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
#     <BuildOptions>
#       GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Bus/Pci/XhciDxe
#   }

  #---------------------------------------------------------------------------
  # NvmExpressDxe - NVM Express host controller driver.
  # L1 harness: mocked PCI I/O, real NvmExpressDxe (register parsing,
  #   admin/IO queue management, namespace enumeration).
  # Consumed protocols: PCI_IO (mock), DevicePath (mock).
  # Produced protocols: NVM_EXPRESS_PASS_THRU, BlockIo, BlockIo2 (exercised by harness).
  #---------------------------------------------------------------------------
#   HBFAplus/FuzzHarness/MdeModulePkg/Bus/Pci/NvmExpressDxe/TestNvmExpressDriver/TestNvmExpressDriver.inf {
#     <LibraryClasses>
#       NULL|MdeModulePkg/Bus/Pci/NvmExpressDxe/NvmExpressDxe.inf
#       NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
#     <BuildOptions>
#       GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Bus/Pci/NvmExpressDxe
#   }

  #---------------------------------------------------------------------------
  # SdMmcPciHcDxe - SD/MMC PCI Host Controller driver.
  # L1 harness: mocked PCI I/O, real SdMmcPciHcDxe (SDHCI register parsing,
  #   slot enumeration, card identification, ADMA descriptor handling).
  # Consumed protocols: PCI_IO (mock), DevicePath (mock).
  # Produced protocols: SD_MMC_PASS_THRU (exercised by harness).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Bus/Pci/SdMmcPciHcDxe/TestSdMmcPciHcDriver/TestSdMmcPciHcDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Bus/Pci/SdMmcPciHcDxe/SdMmcPciHcDxe.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Bus/Pci/SdMmcPciHcDxe
  }

  #---------------------------------------------------------------------------
  # GraphicsOutputDxe - Generic GOP driver for PCI display controllers.
  # L1 harness: mocked PCI I/O, real GraphicsOutputDxe (GOP QueryMode,
  #   SetMode, Blt operations with FrameBufferBltLib).
  # Consumed protocols: PCI_IO (mock), DevicePath (mock).
  # Consumed HOBs: gEfiGraphicsInfoHobGuid, gEfiGraphicsDeviceInfoHobGuid.
  # Produced protocols: GRAPHICS_OUTPUT (exercised by harness).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Universal/Console/GraphicsOutputDxe/TestGraphicsOutputDriver/TestGraphicsOutputDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/Console/GraphicsOutputDxe/GraphicsOutputDxe.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/Console/GraphicsOutputDxe
  }

  #---------------------------------------------------------------------------
  # DiskIoDxe - Byte-level disk I/O over block devices.
  # L1 harness: mocked Block I/O for ReadBlocks/WriteBlocks.
  # Consumed protocols: BLOCK_IO (mock).
  # Produced/exercised protocols: EFI_DISK_IO_PROTOCOL (ReadDisk, WriteDisk).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Universal/Disk/DiskIoDxe/TestDiskIoDriver/TestDiskIoDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIoDxe.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Universal/Disk/DiskIoDxe/MockgEfiBlockIoProtocolGuid/MockgEfiBlockIoProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/Disk/DiskIoDxe
  }

  #---------------------------------------------------------------------------
  # SataControllerDxe - SATA/IDE controller init protocol.
  # L1 harness: mocked PCI I/O for AHCI register access.
  # Consumed protocols: PCI_IO (mock).
  # Produced/exercised protocols: EFI_IDE_CONTROLLER_INIT_PROTOCOL.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Bus/Pci/SataControllerDxe/TestSataControllerDriver/TestSataControllerDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Bus/Pci/SataControllerDxe/SataControllerDxe.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Bus/Pci/SataControllerDxe
  }

  #---------------------------------------------------------------------------
  # IncompatiblePciDeviceSupportDxe - Incompatible PCI device support.
  # L1 harness: no mock dependencies — self-contained singleton driver.
  # Consumed protocols: NONE.
  # Produced/exercised protocols: EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Bus/Pci/IncompatiblePciDeviceSupportDxe/TestIncompatPciDriver/TestIncompatPciDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Bus/Pci/IncompatiblePciDeviceSupportDxe/IncompatiblePciDeviceSupportDxe.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Bus/Pci/IncompatiblePciDeviceSupportDxe
  }

  #---------------------------------------------------------------------------
  # DpcDxe - Deferred Procedure Call protocol.
  # L1 harness: no mock dependencies — self-contained singleton service driver.
  # Consumed protocols: NONE.
  # Produced/exercised protocols: EFI_DPC_PROTOCOL (QueueDpc, DispatchDpc).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/DpcDxe/TestDpcDriver/TestDpcDriver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/DpcDxe/DpcDxe.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/DpcDxe
  }

  #---------------------------------------------------------------------------
  # SnpDxe - Simple Network Protocol via PXE UNDI commands.
  # L1 harness: mocked NII 3.1 (PXE_UNDI entry point) + PCI I/O.
  # Consumed protocols: NII_31 (mock), PCI_IO (mock), DevicePath (mock).
  # Produced/exercised protocols: EFI_SIMPLE_NETWORK_PROTOCOL.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/SnpDxe/TestSnpDriver/TestSnpDriver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/SnpDxe/SnpDxe.inf
      NULL|HBFAplus/MockProtocols/MdePkg/NetworkInterfaceIdentifierDxe/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/SnpDxe
  }

  #---------------------------------------------------------------------------
  # UefiPxeBcDxe - PXE Base Code protocol (IPv4+IPv6 PXE boot).
  # L1 harness: 25 mock protocol dependencies — all pre-existing.
  # Consumed protocols: ARP, IP4/6, UDP4/6, MTFTP4/6, DHCP4/6, DNS6,
  #   NII_31, PciIo (DevicePath), AdapterInformation.
  # Produced/exercised protocols: EFI_PXE_BASE_CODE_PROTOCOL.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/UefiPxeBcDxe/TestPxeBcDriver/TestPxeBcDriver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/UefiPxeBcDxe/UefiPxeBcDxe.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/NetworkInterfaceIdentifierDxe/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpServiceBindingProtocolGuid/MockgEfiArpServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpProtocolGuid/MockgEfiArpProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ServiceBindingProtocolGuid/MockgEfiIp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ProtocolGuid/MockgEfiIp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4Config2ProtocolGuid/MockgEfiIp4Config2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp4Dxe/MockgEfiUdp4ServiceBindingProtocolGuid/MockgEfiUdp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp4Dxe/MockgEfiUdp4ProtocolGuid/MockgEfiUdp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ServiceBindingProtocolGuid/MockgEfiUdp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ProtocolGuid/MockgEfiUdp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Mtftp4Dxe/MockgEfiMtftp4ServiceBindingProtocolGuid/MockgEfiMtftp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Mtftp4Dxe/MockgEfiMtftp4ProtocolGuid/MockgEfiMtftp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Mtftp6Dxe/MockgEfiMtftp6ServiceBindingProtocolGuid/MockgEfiMtftp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Mtftp6Dxe/MockgEfiMtftp6ProtocolGuid/MockgEfiMtftp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ServiceBindingProtocolGuid/MockgEfiDhcp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ProtocolGuid/MockgEfiDhcp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp6Dxe/MockgEfiDhcp6ServiceBindingProtocolGuid/MockgEfiDhcp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp6Dxe/MockgEfiDhcp6ProtocolGuid/MockgEfiDhcp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ServiceBindingProtocolGuid/MockgEfiDns6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ProtocolGuid/MockgEfiDns6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/AdapterInformationDxe/MockgEfiAdapterInformationProtocolGuid/MockgEfiAdapterInformationProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/UefiPxeBcDxe
  }

  #---------------------------------------------------------------------------
  # PxeBcDxe L1L2 Deep — real Udp4Dxe → real PxeBcDxe, IP4 layer mocked
  #
  # Mock boundary: IP4 (gEfiIp4ProtocolGuid)
  # BUG CLASS: UDP4↔PXE interaction bugs invisible to shallow harness.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/UefiPxeBcDxe/TestPxeBcDriverL1L2Deep/TestPxeBcDriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Udp4Dxe/Udp4Dxe.inf
      NULL|NetworkPkg/UefiPxeBcDxe/UefiPxeBcDxe.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ProtocolGuid/MockgEfiIp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ServiceBindingProtocolGuid/MockgEfiIp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4Config2ProtocolGuid/MockgEfiIp4Config2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/NetworkInterfaceIdentifierDxe/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpServiceBindingProtocolGuid/MockgEfiArpServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/ArpDxe/MockgEfiArpProtocolGuid/MockgEfiArpProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ServiceBindingProtocolGuid/MockgEfiUdp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ProtocolGuid/MockgEfiUdp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Mtftp4Dxe/MockgEfiMtftp4ServiceBindingProtocolGuid/MockgEfiMtftp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Mtftp4Dxe/MockgEfiMtftp4ProtocolGuid/MockgEfiMtftp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Mtftp6Dxe/MockgEfiMtftp6ServiceBindingProtocolGuid/MockgEfiMtftp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Mtftp6Dxe/MockgEfiMtftp6ProtocolGuid/MockgEfiMtftp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ServiceBindingProtocolGuid/MockgEfiDhcp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ProtocolGuid/MockgEfiDhcp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp6Dxe/MockgEfiDhcp6ServiceBindingProtocolGuid/MockgEfiDhcp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp6Dxe/MockgEfiDhcp6ProtocolGuid/MockgEfiDhcp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ServiceBindingProtocolGuid/MockgEfiDns6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ProtocolGuid/MockgEfiDns6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/AdapterInformationDxe/MockgEfiAdapterInformationProtocolGuid/MockgEfiAdapterInformationProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/UefiPxeBcDxe -I$(WORKSPACE)/edk2/NetworkPkg/Udp4Dxe
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # TlsDxe - SKIPPED: Requires full OpenSSL crypto stack (BaseCryptLib +
  # TlsLib + OpensslLib + IntrinsicLib). EDK2's SysCall/CrtWrapper.c
  # overrides libc's fopen/printf/stderr with NULL stubs, making host-based
  # fuzzing impractical without a full libc-compatible BaseCryptLib.
  #
  # TLS protocol: SetSessionData, GetSessionData, BuildResponsePacket,
  #               ProcessPacket.
  # TLS Configuration protocol: SetData, GetData.
  # ServiceBinding: CreateChild, DestroyChild.
  #---------------------------------------------------------------------------
  # HBFAplus/FuzzHarness/NetworkPkg/TlsDxe/TestTlsDriver/TestTlsDriver.inf

  #---------------------------------------------------------------------------
  # HttpDxe - HTTP protocol.  L1 harness with mock TCP4/6, DNS, TLS, etc.
  # TLS is consumed via protocol (no BaseCryptLib), so fully mockable.
  # Consumed protocols: TCP4/6 SB+proto, DNS4/6 SB+proto, TLS SB+proto+config,
  #   Ip4Config2, Ip6Config, HttpUtilities, HttpCallback, RNG.
  # Produced/exercised protocols: EFI_HTTP_PROTOCOL (Configure, Request, Response).
  #---------------------------------------------------------------------------
#   HBFAplus/FuzzHarness/NetworkPkg/HttpDxe/TestHttpDriver/TestHttpDriver.inf {
#     <LibraryClasses>
#       NULL|NetworkPkg/HttpDxe/HttpDxe.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp4ServiceBindingProtocolGuid/MockgEfiTcp4ServiceBindingProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp4ProtocolGuid/MockgEfiTcp4ProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp6ServiceBindingProtocolGuid/MockgEfiTcp6ServiceBindingProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp6ProtocolGuid/MockgEfiTcp6ProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns4ServiceBindingProtocolGuid/MockgEfiDns4ServiceBindingProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns4ProtocolGuid/MockgEfiDns4ProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ServiceBindingProtocolGuid/MockgEfiDns6ServiceBindingProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ProtocolGuid/MockgEfiDns6ProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4Config2ProtocolGuid/MockgEfiIp4Config2ProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsServiceBindingProtocolGuid/MockgEfiTlsServiceBindingProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsProtocolGuid/MockgEfiTlsProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsConfigurationProtocolGuid/MockgEfiTlsConfigurationProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/HttpDxe/MockgEdkiiHttpCallbackProtocolGuid/MockgEdkiiHttpCallbackProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/HttpUtilitiesDxe/MockgEfiHttpUtilitiesProtocolGuid/MockgEfiHttpUtilitiesProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
#     <BuildOptions>
#       GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/HttpDxe
#   }

  #---------------------------------------------------------------------------
  # HttpDxe L1L2 Deep - Real TcpDxe + HttpDxe with IP4/IP6-level mock boundary.
  #---------------------------------------------------------------------------
#   HBFAplus/FuzzHarness/NetworkPkg/HttpDxe/TestHttpDriverL1L2Deep/TestHttpDriverL1L2Deep.inf {
#     <LibraryClasses>
#       NULL|NetworkPkg/TcpDxe/TcpDxe.inf
#       NULL|NetworkPkg/HttpDxe/HttpDxe.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ProtocolGuid/MockgEfiIp4ProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ServiceBindingProtocolGuid/MockgEfiIp4ServiceBindingProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4Config2ProtocolGuid/MockgEfiIp4Config2ProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns4ServiceBindingProtocolGuid/MockgEfiDns4ServiceBindingProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns4ProtocolGuid/MockgEfiDns4ProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ServiceBindingProtocolGuid/MockgEfiDns6ServiceBindingProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ProtocolGuid/MockgEfiDns6ProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsServiceBindingProtocolGuid/MockgEfiTlsServiceBindingProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsProtocolGuid/MockgEfiTlsProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsConfigurationProtocolGuid/MockgEfiTlsConfigurationProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/HttpDxe/MockgEdkiiHttpCallbackProtocolGuid/MockgEdkiiHttpCallbackProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/HttpUtilitiesDxe/MockgEfiHttpUtilitiesProtocolGuid/MockgEfiHttpUtilitiesProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ProtocolGuid/MockgEfiHash2ProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ServiceBindingProtocolGuid/MockgEfiHash2ServiceBindingProtocolGuid.inf
#       NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
#     <BuildOptions>
#       GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/HttpDxe -I$(WORKSPACE)/edk2/NetworkPkg/TcpDxe
#       GCC:*_*_*_DLINK_FLAGS = -Wl,--wrap=TcpChecksum -Wl,--allow-multiple-definition
#   }

  #---------------------------------------------------------------------------
  # SmmLockBox - SMM lock-box handler (security-critical CommBuffer parsing).
  # L1 harness: exercises REAL SmmLockBox SMI handler with fuzz CommBuffer.
  # Consumed protocols: EFI_SMM_BASE2 (mock), EFI_SMM_COMMUNICATION (mock).
  # Produced/exercised: gEfiSmmLockBoxCommunicationGuid SMI handler.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Universal/LockBox/SmmLockBox/TestSmmLockBoxDriver/TestSmmLockBoxDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/LockBox/SmmLockBox/SmmLockBox.inf
      LockBoxLib|HBFAplus/HostLib/LockBoxStubLib/LockBoxStubLib.inf
      NULL|HBFAplus/MockProtocols/MdePkg/SmmServicesTableLib/MockgEfiSmmBase2ProtocolGuid/MockgEfiSmmBase2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/SmmCommunication/MockgEfiSmmCommunicationProtocolGuid/MockgEfiSmmCommunicationProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/LockBox/SmmLockBox
  }

  #---------------------------------------------------------------------------
  # VariableSmm L1 — SMM variable service (security-critical CommBuffer parsing).
  #
  # Runs the real VariableServiceInitialize() entry point with the in-RAM
  # variable store path (PcdEmuVariableNvModeEnable=TRUE) so no FVB / FTW
  # mocks are required.  Once initialised, the harness submits fuzz-controlled
  # SMM_VARIABLE_COMMUNICATE_HEADER + payload buffers via gMmst->MmiManage().
  #
  # Fuzz surface:
  #   SmmVariableHandler header / payload-size validation, GET/SET/QUERY/LOCK,
  #   GET_NEXT_VARIABLE_NAME, VAR_CHECK_VARIABLE_PROPERTY_SET/GET, payload-size
  #   query, READY_TO_BOOT / EXIT_BOOT_SERVICE state flips, raw CommBuffer.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Universal/Variable/RuntimeDxe/TestVariableSmmDriver/TestVariableSmmDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm.inf
      NULL|HBFAplus/MockProtocols/MdePkg/SmmServicesTableLib/MockgEfiSmmBase2ProtocolGuid/MockgEfiSmmBase2ProtocolGuid.inf
      AuthVariableLib|MdeModulePkg/Library/AuthVariableLibNull/AuthVariableLibNull.inf
      VarCheckLib|MdeModulePkg/Library/VarCheckLib/VarCheckLib.inf
      VariableFlashInfoLib|MdeModulePkg/Library/BaseVariableFlashInfoLib/BaseVariableFlashInfoLib.inf
    <PcdsFixedAtBuild>
      # Bypass FVB / FTW: in-RAM variable store, allocated by AllocateRuntimePool.
      gEfiMdeModulePkgTokenSpaceGuid.PcdEmuVariableNvModeEnable|TRUE
      # Bound the variable store + payloads so each fuzz iteration stays small.
      gEfiMdeModulePkgTokenSpaceGuid.PcdVariableStoreSize|0x10000
      gEfiMdeModulePkgTokenSpaceGuid.PcdMaxVariableSize|0x2000
      gEfiMdeModulePkgTokenSpaceGuid.PcdMaxAuthVariableSize|0x2800
      gEfiMdeModulePkgTokenSpaceGuid.PcdMaxVolatileVariableSize|0x2000
      gEfiMdeModulePkgTokenSpaceGuid.PcdMaxHardwareErrorVariableSize|0x2000
      gEfiMdeModulePkgTokenSpaceGuid.PcdHwErrStorageSize|0x2000
      gEfiMdeModulePkgTokenSpaceGuid.PcdMaxUserNvVariableSpaceSize|0x4000
      gEfiMdeModulePkgTokenSpaceGuid.PcdBoottimeReservedNvVariableSpaceSize|0x1000
      # Skip end-of-DXE reclaim (avoids reentrant variable-store walk during init).
      gEfiMdeModulePkgTokenSpaceGuid.PcdReclaimVariableSpaceAtEndOfDxe|FALSE
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/Variable/RuntimeDxe
  }

  #---------------------------------------------------------------------------
  # VarCheckPolicyLib L1 — Library-level fuzz harness for the MMI handler that
  # implements VAR_CHECK_POLICY_COMM_HEADER processing (DISABLE / IS_ENABLED /
  # REGISTER / DUMP / LOCK / GET_INFO / GET_LOCK_VAR_STATE_INFO).
  #
  # Links VarCheckPolicyLib (Traditional) as NULL so its handler implementation
  # is available; the harness then manually invokes its constructor to register
  # the handler under gVarCheckPolicyLibMmiHandlerGuid and dispatches fuzz
  # CommBuffers via gMmst->MmiManage().  No flash / variable / FTW mocks are
  # needed — VariableServiceGetVariable is stubbed in the harness to satisfy
  # InitVariablePolicyLib().
  #
  # Fuzz surface:
  #   Header signature/revision/size validation, REGISTER VARIABLE_POLICY_ENTRY
  #   parsing (Size, Version, OffsetToName, name region overflow), DUMP
  #   pagination cache state machine, GET_INFO Safe* arithmetic, LOCK state
  #   transition, raw CommBuffer.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Library/VarCheckPolicyLib/TestVarCheckPolicyLib/TestVarCheckPolicyLib.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Library/VarCheckPolicyLib/VarCheckPolicyLib.inf
      NULL|HBFAplus/MockProtocols/MdePkg/SmmServicesTableLib/MockgEfiSmmBase2ProtocolGuid/MockgEfiSmmBase2ProtocolGuid.inf
      VarCheckLib|MdeModulePkg/Library/VarCheckLib/VarCheckLib.inf
  }

  #---------------------------------------------------------------------------
  # AuthVariableLib L1 — library-level fuzz harness for Secure Boot variable
  # parsing.  Drives AuthVariableLibProcessVariable() with fuzz-controlled
  # EFI_VARIABLE_AUTHENTICATION_2 envelopes / EFI_SIGNATURE_LIST chains /
  # raw payloads, with an in-memory backing store for the Find/Update
  # callbacks the library needs.
  #
  # BaseCryptLibNull is intentional: PKCS7/X.509 verify always returns
  # SUCCESS so the fuzzer can reach the parsing surface (AUTHINFO2 length
  # arithmetic, WIN_CERTIFICATE_UEFI_GUID validation, time-stamp comparison,
  # EFI_SIGNATURE_LIST traversal, certdb encode/decode, SetupMode/CustomMode
  # state-transition logic) without crypto blocking discovery.
  #
  # Bug class: pre-crypto parsing bugs reachable from any caller that can
  # SetVariable an authenticated variable (CVE-2014-4859, CVE-2018-12180,
  # CVE-2022-1739 family).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/SecurityPkg/Library/AuthVariableLib/TestAuthVariableLib/TestAuthVariableLib.inf {
    <LibraryClasses>
      AuthVariableLib|SecurityPkg/Library/AuthVariableLib/AuthVariableLib.inf
      BaseCryptLib|HBFAplus/HostLib/BaseCryptLibPermissiveStub/BaseCryptLibPermissiveStub.inf
      PlatformSecureLib|SecurityPkg/Library/PlatformSecureLibNull/PlatformSecureLibNull.inf
      VariablePolicyLib|MdeModulePkg/Library/VariablePolicyLib/VariablePolicyLib.inf
      VariablePolicyHelperLib|MdeModulePkg/Library/VariablePolicyHelperLib/VariablePolicyHelperLib.inf
  }

  #---------------------------------------------------------------------------
  # DisplayEngineDxe L1 — Component-level fuzz harness for HII Popup Protocol.
  #
  # Runs the real DisplayEngineDxe entry point (InitializeDisplayEngine) which
  # installs EFI_HII_POPUP_PROTOCOL.  Exercises CreatePopup with fuzz-controlled
  # message strings and key inputs.  CustomizedDisplayLib is a stub (all no-ops).
  # Fuzz surface: ParseMessageString, GetStringOffsetWithWidth, CalculatePopupPosition,
  # DrawMessageBox string truncation, GetUserSelection key input handling.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Universal/DisplayEngineDxe/TestDisplayEngineDriver/TestDisplayEngineDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/DisplayEngineDxe/DisplayEngineDxe.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      CustomizedDisplayLib|HBFAplus/HostLib/CustomizedDisplayLibStub/CustomizedDisplayLibStub.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/DisplayEngineDxe
  }

  #---------------------------------------------------------------------------
  # DisplayEngineDxe L1L2Deep — 3-driver stack:
  #   real HiiDatabaseDxe → real SetupBrowserDxe → real DisplayEngineDxe
  # No mock protocols needed — all dependencies are pure software.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Universal/DisplayEngineDxe/TestDisplayEngineDriverL1L2Deep/TestDisplayEngineDriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf
      NULL|MdeModulePkg/Universal/SetupBrowserDxe/SetupBrowserDxe.inf
      NULL|MdeModulePkg/Universal/DisplayEngineDxe/DisplayEngineDxe.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      CustomizedDisplayLib|HBFAplus/HostLib/CustomizedDisplayLibStub/CustomizedDisplayLibStub.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/DisplayEngineDxe -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/HiiDatabaseDxe -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/SetupBrowserDxe
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # IScsiDxe L1 — Component-level fuzz harness for the entire IScsiDxe driver.
  #
  # Exercises the full DriverBinding lifecycle (EntryPoint → Supported → Start
  # → session login) and EFI_EXT_SCSI_PASS_THRU_PROTOCOL APIs.
  # Primary fuzz surface: iSCSI PDU parsing during session login via mock TCP4.
  # Consumed protocols: TCP4/TCP4SB (fuzz data injection), SNP, NII31, PCI IO,
  # ACPI Table, Adapter Information, DPC, RNG.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/IScsiDxe/TestIScsiDriver/TestIScsiDriver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/IScsiDxe/IScsiDxe.inf
      BaseCryptLib|CryptoPkg/Library/BaseCryptLibNull/BaseCryptLibNull.inf
      TcpIoLib|NetworkPkg/Library/DxeTcpIoLib/DxeTcpIoLib.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp4ServiceBindingProtocolGuid/MockgEfiTcp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp4ProtocolGuid/MockgEfiTcp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/NetworkInterfaceIdentifierDxe/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/AcpiTableDxe/MockgEfiAcpiTableProtocolGuid/MockgEfiAcpiTableProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/AdapterInformationDxe/MockgEfiAdapterInformationProtocolGuid/MockgEfiAdapterInformationProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/IScsiDxe
    <PcdsFixedAtBuild>
      gEfiNetworkPkgTokenSpaceGuid.PcdIScsiAIPNetworkBootPolicy|0
  }

  #---------------------------------------------------------------------------
  # IScsiDxe L1L2 Deep — real TcpDxe → real IScsiDxe, IP4 layer mocked
  #
  # Mock boundary: IP4 (gEfiIp4ProtocolGuid)
  # BUG CLASS: TCP↔iSCSI PDU interaction bugs invisible to shallow harness.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/IScsiDxe/TestIScsiDriverL1L2Deep/TestIScsiDriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/TcpDxe/TcpDxe.inf
      NULL|NetworkPkg/IScsiDxe/IScsiDxe.inf
      BaseCryptLib|CryptoPkg/Library/BaseCryptLibNull/BaseCryptLibNull.inf
      TcpIoLib|NetworkPkg/Library/DxeTcpIoLib/DxeTcpIoLib.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ProtocolGuid/MockgEfiIp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4ServiceBindingProtocolGuid/MockgEfiIp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/NetworkInterfaceIdentifierDxe/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/Bus/Pci/PciBusDxe/MockgEfiPciIoProtocolGuid/MockgEfiPciIoProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/AcpiTableDxe/MockgEfiAcpiTableProtocolGuid/MockgEfiAcpiTableProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/AdapterInformationDxe/MockgEfiAdapterInformationProtocolGuid/MockgEfiAdapterInformationProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
      NULL|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ProtocolGuid/MockgEfiHash2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/Hash2Dxe/MockgEfiHash2ServiceBindingProtocolGuid/MockgEfiHash2ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/IScsiDxe -I$(WORKSPACE)/edk2/NetworkPkg/TcpDxe
      GCC:*_*_*_DLINK_FLAGS = -Wl,--wrap=TcpChecksum -Wl,--allow-multiple-definition
    <PcdsFixedAtBuild>
      gEfiNetworkPkgTokenSpaceGuid.PcdIScsiAIPNetworkBootPolicy|0
  }

  #---------------------------------------------------------------------------
  # FirmwareVolumeBlock - Component harness using EmuVariableFvbRuntimeDxe (OvmfPkg).
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/OvmfPkg/EmuVariableFvbRuntimeDxe/TestEmuVariableFvbDriver/TestEmuVariableFvbDriver.inf {
    <LibraryClasses>
      PcdLib|HBFAplus/HostLib/PcdLibHostDynamic/PcdLibHostDynamic.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/OvmfPkg/EmuVariableFvbRuntimeDxe
  }



  #---------------------------------------------------------------------------
  # HttpBootDxe L1 — Component-level fuzz harness.
  #
  # Runs the real HttpBootDxe entry point which installs IPv4/IPv6 DriverBindings,
  # then exercises the EFI_LOAD_FILE_PROTOCOL produced by Start().
  # LoadFile triggers: HttpBootStart → HttpBootDhcp → HttpBootGetBootFile.
  # Fuzz surfaces: DHCP offer parsing, HTTP response parsing, URI parsing,
  #   callback invocations, device path construction.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/HttpBootDxe/TestHttpBootDriver/TestHttpBootDriver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/HttpBootDxe/HttpBootDxe.inf
      HttpIoLib|NetworkPkg/Library/DxeHttpIoLib/DxeHttpIoLib.inf
      UefiBootManagerLib|HBFAplus/HostLib/UefiBootManagerLibNull/UefiBootManagerLibNull.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ServiceBindingProtocolGuid/MockgEfiDhcp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ProtocolGuid/MockgEfiDhcp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp6Dxe/MockgEfiDhcp6ServiceBindingProtocolGuid/MockgEfiDhcp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp6Dxe/MockgEfiDhcp6ProtocolGuid/MockgEfiDhcp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/HttpDxe/MockgEfiHttpServiceBindingProtocolGuid/MockgEfiHttpServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/HttpDxe/MockgEfiHttpProtocolGuid/MockgEfiHttpProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4Config2ProtocolGuid/MockgEfiIp4Config2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ServiceBindingProtocolGuid/MockgEfiDns6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ProtocolGuid/MockgEfiDns6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/NetworkInterfaceIdentifierDxe/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31.inf
      NULL|HBFAplus/MockProtocols/MdePkg/AdapterInformationDxe/MockgEfiAdapterInformationProtocolGuid/MockgEfiAdapterInformationProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/RamDiskDxe/MockgEfiRamDiskProtocolGuid/MockgEfiRamDiskProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/HttpBootCallbackDxe/MockgEfiHttpBootCallbackProtocolGuid/MockgEfiHttpBootCallbackProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/HttpBootDxe
  }

  #---------------------------------------------------------------------------
  # HttpBootDxe L1L2 Deep — real HttpDxe → real HttpBootDxe, TCP layer mocked
  #
  # Mock boundary: TCP4/TCP6 (gEfiTcp4ProtocolGuid / gEfiTcp6ProtocolGuid)
  # BUG CLASS: HTTP↔HttpBoot interaction bugs invisible to shallow harness.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/NetworkPkg/HttpBootDxe/TestHttpBootDriverL1L2Deep/TestHttpBootDriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|NetworkPkg/HttpDxe/HttpDxe.inf
      NULL|NetworkPkg/HttpBootDxe/HttpBootDxe.inf
      HttpIoLib|NetworkPkg/Library/DxeHttpIoLib/DxeHttpIoLib.inf
      UefiBootManagerLib|HBFAplus/HostLib/UefiBootManagerLibNull/UefiBootManagerLibNull.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp4ServiceBindingProtocolGuid/MockgEfiTcp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp4ProtocolGuid/MockgEfiTcp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp6ServiceBindingProtocolGuid/MockgEfiTcp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/TcpDxe/MockgEfiTcp6ProtocolGuid/MockgEfiTcp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsProtocolGuid/MockgEfiTlsProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsServiceBindingProtocolGuid/MockgEfiTlsServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/TlsDxe/MockgEfiTlsConfigurationProtocolGuid/MockgEfiTlsConfigurationProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/HttpUtilitiesDxe/MockgEfiHttpUtilitiesProtocolGuid/MockgEfiHttpUtilitiesProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ServiceBindingProtocolGuid/MockgEfiDhcp4ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp4Dxe/MockgEfiDhcp4ProtocolGuid/MockgEfiDhcp4ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp6Dxe/MockgEfiDhcp6ServiceBindingProtocolGuid/MockgEfiDhcp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Dhcp6Dxe/MockgEfiDhcp6ProtocolGuid/MockgEfiDhcp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip4Dxe/MockgEfiIp4Config2ProtocolGuid/MockgEfiIp4Config2ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ServiceBindingProtocolGuid/MockgEfiDns6ServiceBindingProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DnsDxe/MockgEfiDns6ProtocolGuid/MockgEfiDns6ProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/NetworkInterfaceIdentifierDxe/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31.inf
      NULL|HBFAplus/MockProtocols/MdePkg/AdapterInformationDxe/MockgEfiAdapterInformationProtocolGuid/MockgEfiAdapterInformationProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/RamDiskDxe/MockgEfiRamDiskProtocolGuid/MockgEfiRamDiskProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdePkg/HttpBootCallbackDxe/MockgEfiHttpBootCallbackProtocolGuid/MockgEfiHttpBootCallbackProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|HBFAplus/MockProtocols/MdeModulePkg/HiiDatabaseDxe/MockHiiDatabaseProtocol/MockHiiDatabaseProtocol.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/NetworkPkg/HttpBootDxe -I$(WORKSPACE)/edk2/NetworkPkg/HttpDxe
      GCC:*_*_*_DLINK_FLAGS = -Wl,--allow-multiple-definition
  }

  #---------------------------------------------------------------------------
  # S3SaveStateDxe L1 — Component-level fuzz harness.
  #
  # Runs the real S3SaveStateDxe entry point (InitializeS3SaveState) which
  # installs EFI_S3_SAVE_STATE_PROTOCOL.  Exercises all 17 opcode handlers
  # in the variadic argument dispatch code (Write, Insert, Label, Compare).
  # S3BootScriptLib is BaseS3BootScriptLibNull (all no-op); fuzz surface is
  # the opcode dispatch + VA_ARG extraction in S3SaveState.c.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Universal/Acpi/S3SaveStateDxe/TestS3SaveStateDriver/TestS3SaveStateDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/Acpi/S3SaveStateDxe/S3SaveStateDxe.inf
      S3BootScriptLib|MdePkg/Library/BaseS3BootScriptLibNull/BaseS3BootScriptLibNull.inf
      SmbusLib|MdePkg/Library/BaseSmbusLibNull/BaseSmbusLibNull.inf
      LockBoxLib|HBFAplus/HostLib/LockBoxStubLib/LockBoxStubLib.inf
    <PcdsFixedAtBuild>
      gEfiMdeModulePkgTokenSpaceGuid.PcdAcpiS3Enable|TRUE
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/Acpi/S3SaveStateDxe
  }

  #---------------------------------------------------------------------------
  # S3SaveStateDxe L1+L2 Deep — Real SmmLockBox + real S3SaveStateDxe.
  #
  # SmmLockBox registers SMI handler and installs gEfiLockBoxProtocolGuid.
  # S3SaveStateDxe installs EFI_S3_SAVE_STATE_PROTOCOL.  Same 17 opcode
  # handlers as L1 but with real SmmLockBox code in the init path.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Universal/Acpi/S3SaveStateDxe/TestS3SaveStateDriverL1L2Deep/TestS3SaveStateDriverL1L2Deep.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/Acpi/S3SaveStateDxe/S3SaveStateDxe.inf
      NULL|MdeModulePkg/Universal/LockBox/SmmLockBox/SmmLockBox.inf
      NULL|HBFAplus/MockProtocols/MdePkg/SmmServicesTableLib/MockgEfiSmmBase2ProtocolGuid/MockgEfiSmmBase2ProtocolGuid.inf
      S3BootScriptLib|MdePkg/Library/BaseS3BootScriptLibNull/BaseS3BootScriptLibNull.inf
      SmbusLib|MdePkg/Library/BaseSmbusLibNull/BaseSmbusLibNull.inf
      LockBoxLib|HBFAplus/HostLib/LockBoxStubLib/LockBoxStubLib.inf
    <PcdsFixedAtBuild>
      gEfiMdeModulePkgTokenSpaceGuid.PcdAcpiS3Enable|TRUE
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/Acpi/S3SaveStateDxe -I$(WORKSPACE)/edk2/MdeModulePkg/Universal/LockBox/SmmLockBox
  }

  #---------------------------------------------------------------------------
  # PciHostBridgeDxe L1 — Component-level fuzz harness.
  #
  # Runs the real PciHostBridgeDxe entry point (InitializePciHostBridge) which
  # creates PCI_ROOT_BRIDGE_INSTANCE and installs EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.
  # Fuzz surface: CpuIo2 Mem/Io reads deliver fuzz bytes through the real driver
  # to exercise parameter validation, aperture checking, and I/O routing.
  #---------------------------------------------------------------------------
  HBFAplus/FuzzHarness/MdeModulePkg/Bus/Pci/PciHostBridgeDxe/TestPciHostBridgeDriver/TestPciHostBridgeDriver.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Bus/Pci/PciHostBridgeDxe/PciHostBridgeDxe.inf
      NULL|HBFAplus/MockProtocols/MdePkg/CpuIo2Dxe/MockgEfiCpuIo2ProtocolGuid/MockgEfiCpuIo2ProtocolGuid.inf
      PciHostBridgeLib|HBFAplus/HostLib/PciHostBridgeLibHost/PciHostBridgeLibHost.inf
      PciSegmentLib|HBFAplus/HostLib/PciSegmentLibHost/PciSegmentLibHost.inf
  }
# Components - Unit Tests
#=============================================================================

[Components]

  #---------------------------------------------------------------------------
  # Host Library Tests
  #---------------------------------------------------------------------------
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/EventHostTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost
  }
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/ProtocolHostTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost
  }
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/EventPumpAutoTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost
  }
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/StallAndConnectTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost
  }
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/MiscServicesTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost
  }
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/UdpIoEventChainTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost -I$(WORKSPACE)/HBFAplus/MockProtocols/Include
  }
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/MemoryServicesTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost
  }
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/TplAndLockTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost
  }
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/HandleDatabaseExtTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost
  }
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/BootServicesGapTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost
  }
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/EventSpecComplianceTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost
  }
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/TplAndResetTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiBootServicesTableLibHost
  }
  HBFAplus/tests/HostLib/UefiRuntimeServicesTableLibHost/RuntimeServicesTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/UefiRuntimeServicesTableLibHost
  }
  HBFAplus/tests/HostLib/RegisterFilterLibHost/RegisterFilterLibHostTest.inf
  HBFAplus/tests/HostLib/FuzzContextLib/FuzzContextLibFlowTest.inf
  HBFAplus/tests/HostLib/FuzzContextLib/FuzzContextSubContextTest.inf
  HBFAplus/tests/HostLib/BaseMemoryLibHost/BaseMemoryLibHostTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/BaseMemoryLibHost
  }
  HBFAplus/tests/HostLib/BaseTimerLibHost/BaseTimerLibHostTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/BaseTimerLibHost
  }
  HBFAplus/tests/HostLib/BaseLibHost/BaseLibHostTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/BaseLibHost
  }
  HBFAplus/tests/HostLib/BaseCacheMaintenanceLibHost/BaseCacheMaintenanceLibHostTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/BaseCacheMaintenanceLibHost
  }
  HBFAplus/tests/HostLib/DebugLibHost/DebugLibHostTest.inf
  HBFAplus/tests/HostLib/PrintLibHost/PrintLibHostTest.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/HBFAplus/HostLib/PrintLibHost
  }
  HBFAplus/tests/HostLib/DxeServicesTableLibHost/DxeServicesTableLibHostTest.inf
  HBFAplus/tests/HostLib/HobLibHost/HobLibHostTest.inf
  HBFAplus/tests/HostLib/MemoryAllocationLibHost/MemoryAllocationLibHostTest.inf
  HBFAplus/tests/HostLib/PeimEntryPointHost/PeimEntryPointHostTest.inf
  HBFAplus/tests/HostLib/PeiServicesTablePointerLibHost/PeiServicesTablePointerLibHostTest.inf
  HBFAplus/tests/HostLib/SimpleSynchronizationLib/SimpleSynchronizationLibTest.inf
  HBFAplus/tests/HostLib/SmmMemLibHost/SmmMemLibHostTest.inf
  HBFAplus/tests/HostLib/SmmServicesTableLibHost/SmmServicesTableLibHostTest.inf
  HBFAplus/tests/HostLib/UefiDevicePathLibHost/UefiDevicePathLibHostTest.inf
  HBFAplus/tests/HostLib/UefiDriverEntryPointHost/UefiDriverEntryPointHostTest.inf
  HBFAplus/tests/HostLib/UefiDriverEntryPointHost/UefiDriverEntryPointHostTest.inf
  HBFAplus/tests/HostLib/HostDispatcherLib/HostDispatcherLibTest.inf
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/EventDispatchModelTest.inf

  #---------------------------------------------------------------------------
  # Mock Protocol Tests
  #---------------------------------------------------------------------------
  HBFAplus/tests/MockProtocols/MockFuzzContextTest/MockFuzzContextTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiRngProtocolGuidTest/MockgEfiRngProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiSimpleNetworkProtocolGuidTest/MockgEfiSimpleNetworkProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiIp6ConfigProtocolGuidTest/MockgEfiIp6ConfigProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockPciBusDxeTest/MockPciBusDxeTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiUdp6ProtocolGuidTest/MockgEfiUdp6ProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiUdp6ServiceBindingProtocolGuidTest/MockgEfiUdp6ServiceBindingProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiDpcProtocolGuidTest/MockgEfiDpcProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiSmmBase2ProtocolGuidTest/MockgEfiSmmBase2ProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiSmmCommunicationProtocolGuidTest/MockgEfiSmmCommunicationProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiManagedNetworkProtocolGuidTest/MockgEfiManagedNetworkProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiManagedNetworkServiceBindingProtocolGuidTest/MockgEfiManagedNetworkServiceBindingProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiIp6ProtocolGuidTest/MockgEfiIp6ProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiIp6ServiceBindingProtocolGuidTest/MockgEfiIp6ServiceBindingProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiTcp6ProtocolGuidTest/MockgEfiTcp6ProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiTcp6ServiceBindingProtocolGuidTest/MockgEfiTcp6ServiceBindingProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiIp4ProtocolGuidTest/MockgEfiIp4ProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiIp4ServiceBindingProtocolGuidTest/MockgEfiIp4ServiceBindingProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiIp4Config2ProtocolGuidTest/MockgEfiIp4Config2ProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiUdp4ProtocolGuidTest/MockgEfiUdp4ProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiUdp4ServiceBindingProtocolGuidTest/MockgEfiUdp4ServiceBindingProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiArpProtocolGuidTest/MockgEfiArpProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiArpServiceBindingProtocolGuidTest/MockgEfiArpServiceBindingProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiTcp4ProtocolGuidTest/MockgEfiTcp4ProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiTcp4ServiceBindingProtocolGuidTest/MockgEfiTcp4ServiceBindingProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiTlsProtocolGuidTest/MockgEfiTlsProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiTlsServiceBindingProtocolGuidTest/MockgEfiTlsServiceBindingProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiTlsConfigurationProtocolGuidTest/MockgEfiTlsConfigurationProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiHttpUtilitiesProtocolGuidTest/MockgEfiHttpUtilitiesProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiHttpProtocolGuidTest/MockgEfiHttpProtocolGuidTest.inf
  HBFAplus/tests/MockProtocols/MockgEfiHttpServiceBindingProtocolGuidTest/MockgEfiHttpServiceBindingProtocolGuidTest.inf

  # Phase 3: DHCP + DNS + MTFTP test suites
  HBFAplus/tests/MockProtocols/NetworkPkg/Dhcp4Dxe/TestMockgEfiDhcp4ProtocolGuid/TestMockgEfiDhcp4ProtocolGuid.inf
  HBFAplus/tests/MockProtocols/NetworkPkg/Dhcp4Dxe/TestMockgEfiDhcp4ServiceBindingProtocolGuid/TestMockgEfiDhcp4ServiceBindingProtocolGuid.inf
  HBFAplus/tests/MockProtocols/NetworkPkg/Dhcp6Dxe/TestMockgEfiDhcp6ProtocolGuid/TestMockgEfiDhcp6ProtocolGuid.inf
  HBFAplus/tests/MockProtocols/NetworkPkg/Dhcp6Dxe/TestMockgEfiDhcp6ServiceBindingProtocolGuid/TestMockgEfiDhcp6ServiceBindingProtocolGuid.inf
  HBFAplus/tests/MockProtocols/NetworkPkg/DnsDxe/TestMockgEfiDns4ProtocolGuid/TestMockgEfiDns4ProtocolGuid.inf
  HBFAplus/tests/MockProtocols/NetworkPkg/DnsDxe/TestMockgEfiDns4ServiceBindingProtocolGuid/TestMockgEfiDns4ServiceBindingProtocolGuid.inf
  HBFAplus/tests/MockProtocols/NetworkPkg/DnsDxe/TestMockgEfiDns6ProtocolGuid/TestMockgEfiDns6ProtocolGuid.inf
  HBFAplus/tests/MockProtocols/NetworkPkg/DnsDxe/TestMockgEfiDns6ServiceBindingProtocolGuid/TestMockgEfiDns6ServiceBindingProtocolGuid.inf
  HBFAplus/tests/MockProtocols/NetworkPkg/Mtftp4Dxe/TestMockgEfiMtftp4ProtocolGuid/TestMockgEfiMtftp4ProtocolGuid.inf
  HBFAplus/tests/MockProtocols/NetworkPkg/Mtftp4Dxe/TestMockgEfiMtftp4ServiceBindingProtocolGuid/TestMockgEfiMtftp4ServiceBindingProtocolGuid.inf
  HBFAplus/tests/MockProtocols/NetworkPkg/Mtftp6Dxe/TestMockgEfiMtftp6ProtocolGuid/TestMockgEfiMtftp6ProtocolGuid.inf
  HBFAplus/tests/MockProtocols/NetworkPkg/Mtftp6Dxe/TestMockgEfiMtftp6ServiceBindingProtocolGuid/TestMockgEfiMtftp6ServiceBindingProtocolGuid.inf

  # HII Database mock test
  HBFAplus/tests/MockProtocols/MockHiiDatabaseProtocolTest/MockHiiDatabaseProtocolTest.inf

  # NII_31 mock test
  HBFAplus/tests/MockProtocols/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31Test/MockgEfiNetworkInterfaceIdentifierProtocolGuid_31Test.inf

  # ACPI Table mock test
  HBFAplus/tests/MockProtocols/MockgEfiAcpiTableProtocolGuidTest/MockgEfiAcpiTableProtocolGuidTest.inf

  # Adapter Information mock test
  HBFAplus/tests/MockProtocols/MockgEfiAdapterInformationProtocolGuidTest/MockgEfiAdapterInformationProtocolGuidTest.inf

  # AuthenticationInfo mock test
  HBFAplus/tests/MockProtocols/MockgEfiAuthenticationInfoProtocolGuidTest/MockgEfiAuthenticationInfoProtocolGuidTest.inf

  # HttpCallback mock test
  HBFAplus/tests/MockProtocols/MockgEdkiiHttpCallbackProtocolGuidTest/MockgEdkiiHttpCallbackProtocolGuidTest.inf

  # HiiConfigAccess mock test
  HBFAplus/tests/MockProtocols/MockgEfiHiiConfigAccessProtocolGuidTest/MockgEfiHiiConfigAccessProtocolGuidTest.inf

  # HiiConfigRouting mock test
  HBFAplus/tests/MockProtocols/MockgEfiHiiConfigRoutingProtocolGuidTest/MockgEfiHiiConfigRoutingProtocolGuidTest.inf

  # HiiPopup mock test
  HBFAplus/tests/MockProtocols/MockgEfiHiiPopupProtocolGuidTest/MockgEfiHiiPopupProtocolGuidTest.inf

  # IScsiInitiatorName mock test
  HBFAplus/tests/MockProtocols/MockgEfiIScsiInitiatorNameProtocolGuidTest/MockgEfiIScsiInitiatorNameProtocolGuidTest.inf

  # IpSec2 mock test
  HBFAplus/tests/MockProtocols/MockgEfiIpSec2ProtocolGuidTest/MockgEfiIpSec2ProtocolGuidTest.inf

  # RamDisk mock test
  HBFAplus/tests/MockProtocols/MockgEfiRamDiskProtocolGuidTest/MockgEfiRamDiskProtocolGuidTest.inf

  # Supplicant mock test
  HBFAplus/tests/MockProtocols/MockgEfiSupplicantProtocolGuidTest/MockgEfiSupplicantProtocolGuidTest.inf

  # VlanConfig mock test
  HBFAplus/tests/MockProtocols/MockgEfiVlanConfigProtocolGuidTest/MockgEfiVlanConfigProtocolGuidTest.inf

  # WiFi2 mock test
  HBFAplus/tests/MockProtocols/MockgEfiWiFi2ProtocolGuidTest/MockgEfiWiFi2ProtocolGuidTest.inf

  # EapConfiguration mock test
  HBFAplus/tests/MockProtocols/MockgEfiEapConfigurationProtocolGuidTest/MockgEfiEapConfigurationProtocolGuidTest.inf

  # WiFiProfileSync mock test
  HBFAplus/tests/MockProtocols/MockgEdkiiWiFiProfileSyncProtocolGuidTest/MockgEdkiiWiFiProfileSyncProtocolGuidTest.inf

  # Integration test — links ALL mock libraries
  HBFAplus/tests/MockProtocols/AllMocksIntegrationTest/AllMocksIntegrationTest.inf

  # USB2 HC mock test
  HBFAplus/tests/MockProtocols/MockgEfiUsb2HcProtocolGuidTest/MockgEfiUsb2HcProtocolGuidTest.inf

  # CloseEvent + SubContext + Pending Token integration test
  HBFAplus/tests/HostLib/UefiBootServicesTableLibHost/CloseEventIntegrationTest/CloseEventIntegrationTest.inf

#=============================================================================
# Build Options
#=============================================================================

[BuildOptions]
  GCC:*_*_*_CC_FLAGS = -Wall -Wno-unused-but-set-variable

!include HBFAplus/Conf/HBFAplusBuildOption.dsc