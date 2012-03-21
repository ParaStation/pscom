
                           Installation Notes
                       Broadcom BCM5700 Linux Driver
                              Version 8.2.18
                                08/01/2005

                          Broadcom Corporation
                          16215 Alton Parkway,
                          Irvine, CA 92619-7013

                Copyright (c) 2000-2005 Broadcom Corporation
                           All rights reserved


Table of Contents
=================

  Introduction
  Limitations
  Packaging
  Installing Source RPM Package
  Building Driver From TAR File
  Patching Driver Into Kernel
  Unloading and Removing Driver
  Module Parameters
  Driver Messages
  Statistics
  

Introduction
============

This file describes the Linux driver for the Broadcom NetXtreme BCM5700
series 10/100/1000 Mbps PCI/PCI-X/PCI Express Ethernet Network Controllers.


Limitations
===========

The current version of the driver has been tested on the latest Red Hat, SuSE,
and other Linux distributions for i386, ia64, and x86_64 CPU architectures 
using 2.4.x and 2.6.x kernels. The driver has been tested up to kernel
version 2.4.31 and 2.6.12.

The driver should work on other little endian or big endian CPU architectures,
but only very limited testing has been done on some of these machines. The
Makefile may have to be modified to include architecture specific compile
switches, and some minor changes in the source files may also be required.
On these machines, patching the driver into the kernel is recommended (see
below for instructions).


Packaging
=========

The driver is released in two packaging formats: source RPM and compressed tar
formats. The file names for the two packages are bcm5700-<version>.src.rpm and
bcm5700-<version>.tar.gz respectively. Identical source files to build the
driver are included in both packages. bcm_sup-<version> is a seperate tar file 
that contains additional utilities such as patches and driver diskette images 
for network installation.


Installing Source RPM Package
=============================

The following are general guidelines for installing the driver. Refer to
DISTRIB.TXT for additional installation notes for various Linux distributions.

1. Install the source RPM package:

   rpm -ivh bcm5700-<version>.src.rpm

2. CD to the RPM path and build the binary driver for your kernel:

   cd /usr/src/{redhat,OpenLinux,turbo,packages,rpm ..}

   rpm -bb SPECS/bcm5700.spec

or

   rpmbuild -bb SPECS/bcm5700.spec (for RPM version 4.x.x)

Note that the RPM path is different for different Linux distributions.

3. Install the newly built package (driver and man page):

   rpm -ivh RPMS/i386/bcm5700-<version>.i386.rpm

Note that the --force option is needed if installing on Red Hat 7.2, 7.3,
2.1AS and others that already contain an older version of the driver.

The driver will be installed in the following path:

2.2.x kernels:

    /lib/modules/<kernel_version>/net/bcm5700.o

2.4.x kernels:

    /lib/modules/<kernel_version>/kernel/drivers/net/bcm5700.o

2.4.x kernels with bcm5700 as an addon driver (e.g. Red Hat 7.3, 2.1AS):

    /lib/modules/<kernel_version>/kernel/drivers/net/bcm/bcm5700.o

or

    /lib/modules/<kernel_version>/kernel/drivers/addon/bcm5700/bcm5700.o

2.6.x kernels:

    /lib/modules/<kernel_version>/kernel/drivers/net/bcm5700.ko

2.6.x kernels with bcm5700 as an addon driver (e.g. SuSE 9 SLES):

    /lib/modules/<kernel_version>/kernel/drivers/net/bcm/bcm5700.ko

4. Load the driver:

   modprobe bcm5700

If loading the driver on Red Hat 3 update 4, 2.1 AS or other newer kernels with the
tg3 driver, refer to the "Removing tg3 Driver" in DISTRIB.TXT before loading
the driver.

5. To configure network protocol and address, refer to various Linux
documentations.


Building Driver From TAR File
=============================

The following are general guidelines for installing the driver. Refer to
DISTRIB.TXT for additional installation notes for various Linux distributions.

1. Create a directory and extract the files:

   tar xvzf bcm5700-<version>.tar.gz

2. Build the driver bcm5700.o as a loadable module for the running kernel:

   cd src
   make

3. Test the driver by loading it: 

   insmod bcm5700.o
or
   insmod bcm5700.ko (on 2.6.x kernels)

If loading the driver on Red Hat 3 update 4, 2.1 AS or other newer kernels with the
tg3 driver, refer to the "Removing tg3 Driver" in DISTRIB.TXT before loading
the driver.

4. Install the driver and man page:

   make install

See RPM instructions above for the location of the installed driver.

5. To configure network protocol and address, refer to various Linux
documentations.


Patching Driver Into Kernel (Optional)
======================================

Patch files are included for patching the driver into some of the latest
2.4.x and 2.6.x kernel source trees. This step is optional and can be done
by users familiar with configuring and building the kernel. The patch
will modify the orginal kernel's source code.

The following steps may allow you to patch the driver into a kernel:

1. Select the patch file that matches your kernel and apply the patch:

   patch -p1 -d <kernel_src_root> < bcm5700-<version>-2.4.<x>.patch
   patch -p1 -d <kernel_src_root> < bcm5700-<version>-2.6.<x>.patch

where <version> is the version of the bcm5700 driver and 2.4.<x> is the
version of the kernel to patch (e.g. 2.4.31).

Note: <kernel_src_root> is usually /usr/src/linux or /usr/src/linux-2.4.<x>
Note: <kernel_src_root> is usually /usr/src/linux or /usr/src/linux-2.6.<x>

2. Configure the kernel to include the bcm5700 driver. It can be found
under Network Device Support ---> Ethernet (1000 Mbit) ---> Broadcom BCM5700
support when make menuconfig is run. Select built-in or module for the driver:

   cd <kernel_src_root>
   make menuconfig 

3. Compile the kernel:

   make dep
   make clean
   ....
   ....


Unloading and Removing Driver
=============================

To unload the driver, use ifconfig to bring down all eth# interfaces opened
by the driver, then do the following:

rmmod bcm5700


If the driver was installed using rpm, do the following to remove it:

rpm -e bcm5700


If the driver was installed using make install from the tar file, the driver
bcm5700.o has to be manually deleted from the system. Refer to the section
"Installing Source RPM Package" for the location of the installed driver.


Module Parameters
=================

Optional parameters for the driver can be supplied as command line arguments 
to the insmod command. Typically, these parameters are set in the file
/etc/modules.conf (see the man page for modules.conf). These parameters take
the form

    <parameter>=value[,value,...]

where the multiple values for the same parameter are for multiple NICs
installed in the system.

Note that default or other meaningful values will be used when invalid values
are selected. Some combinations of parameter values may conflict and lead to
failures. The driver cannot detect all such conflicting combinations.

All the parameters are listed below.

line_speed

    Selects the line speed of the link. This parameter is used together with
    full_duplex and auto_speed to select the speed and duplexity of the link
    and the setting of autonegotiation.
    
    The valid values are:
    
    0      Autonegotiate for highest speed supported by link partner (default)
    10     10 Mbps
    100    100 Mbps
    1000   1000 Mbps

    If line_speed is set to 10, 100, or 1000, the NIC will autonegotiate for
    the selected speed (and selected duplexity) if auto_speed is set to 1.
    If auto_speed is set to 0, the selected speed and duplexity will be
    set without autonegotiation. Note that 1000 Mbps must be negotiated for
    copper twisted pair links.

auto_speed

    Enables or disables autonegotiation. The valid values are:

    0      Autonegotiation disabled
    1      Autonegotiation enabled (default)

    Note that this parameter is ignored and assumed 1 if line_speed is set
    to 0.
    
full_duplex

    Selects the duplexity of the link. This paramter is used together with
    line_speed to select the speed and duplexity of the link. Note that this
    parameter is ignored if line_speed is 0.
    
    The valid values are:
    
    0      half duplex
    1      full duplex (default)
    
    
rx_flow_control

    Enables or disables receiving flow control (pause) frames. This parameter
    is used together with auto_flow_control. The valid values are:
    
    0      pause receive disabled
    1      pause receive enabled if auto_flow_control is set to 0, or
           pause receive advertised if auto_flow_control is set to 1 (default)

tx_flow_control

    Enables or disables transmitting flow control (pause) frames. This parameter
    is used together with auto_flow_control. The valid values are:
    
    0      pause transmit disabled
    1      pause transmit enabled if auto_flow_control is set to 0, or
           pause transmit advertised if auto_flow_control is set to 1 (default)

auto_flow_control

    Enables or disables autonegotiation of flow control. This parameter is used
    together with rx_flow_control and tx_flow_control to determine the
    advertised flow control capability. The valid values are:
    
    0      flow control autonegotiation disabled
    1      flow control autonegotiation enabled with capability specified in
           rx_flow_control and tx_flow_control (only valid if line_speed is
           set to 0 or auto_speed is set to 1) (default)

mtu

    Enables jumbo frames up to the specified MTU size. The valid range for
    this parameter is 1500 to 9000. Default is 1500 which is standard
    ethernet (non-jumbo) MTU size. Note that the MTU size excludes the
    ethernet header size of 14 bytes. Actual frame size is MTU size + 14 bytes.
    Jumbo MTU sizes are not supported on BCM5705 chips.

    The MTU size can also be changed using ifconfig after the driver is loaded.
    See the ifconfig man page for details.

tx_checksum

    Enables or disables hardware transmit TCP/UDP checksum. The valid values
    are:

    0      checksum disabled
    1      checksum enabled (default)

rx_checksum

    Enables or disables hardware receive TCP/UDP checksum validation. The
    valid values are:

    0      checksum disabled
    1      checksum enabled (default)

scatter_gather

    Enables or disables scatter-gather and 64-bit DMA on x86. This option is
    only useful when running on TUX-enabled kernels or newer kernels with
    zero-copy TCP. The valid values are:

    0      scatter-gather and 64-bit DMA on x86 disabled
    1      scatter-gather and 64-bit DMA on x86 enabled (default)

nic_tx_bd

    Enables either NIC based or host based transmit buffer descriptors (Tx BDs).
    NIC based Tx BDs may be slightly faster on certain machines on earlier
    2.4 kernels where each transmit packet is usually entirely contiguous. On
    later kernels with scatter-gather and TCP segmentation option, host based
    Tx BDs using DMA transfer are usually faster. NIC based Tx BDs are not
    supported on 5705 family controllers. The valid values are:

    0      NIC based transmit buffer descriptors disabled (using host based
           transmit buffer descriptors) (default)
    1      NIC based transmit buffer descriptors enabled (not supported
           on 5705 family controllers)

tx_pkt_desc_cnt

    Configures the number of transmit descriptors. Default is 120. The
    valid range is from 1 to 511. Note that the driver may not be able to
    allocate the required amount of memory if this parameter is set too high.
    Depending on kernel and CPU architecture, each descriptor may require up
    to about 268 bytes. This parameter should not be set less than 80 if
    adaptive_coalesce (see below) is enabled.

rx_std_desc_cnt

    Configures the number of receive descriptors for frames up to 1528 bytes.
    Default is 200. The valid range is from 1 to 511. This parameter should
    not be set less than 80 on systems with high network traffic. Setting this
    parameter higher allows the NIC to buffer larger bursts of network
    traffic without dropping frames, especially on slower systems. Note that
    the driver may not be able to allocate the required amount of memory if
    this parameter is set too high. Depending on kernel and CPU architecture,
    each descriptor may require up to about 268 bytes. Each descriptor also
    requires a socket buffer of at least 1536 bytes. This parameter should not
    be set less than 50 if adaptive_coalesce (see below) is enabled.

rx_jumbo_desc_cnt

    Configures the number of receive descriptors for jumbo frames larger
    than 1528 bytes. Default is 128 and valid range is from 1 to 255.
    When jumbo frames larger than 1528 bytes are used, this parameter should
    not be set lower than 60 on systems with high network traffic. Setting
    this parameter higher allows the NIC to buffer larger bursts of jumbo
    traffic without dropping frames, especially on slower systems. Depending
    on kernel and CPU architecture, each descriptor may require up to about
    268 bytes. Each descriptor also requires a socket buffer the size of a
    maximum jumbo frame. On systems with insufficient memory, it may be
    necessary to reduce this parameter. This parameter should not be set less
    than 50 if adaptive_coalesce (see below) is enabled. When the maximum
    frame size is 1528 or smaller (MTU size 1514 or smaller), this parameter
    is not used and is always 0.

adaptive_coalesce

    Enables or disables adaptive adjustments to the various interrupt
    coalescing parameters. Enabling it allows the driver to dynamically
    adjust the interrupt coalescing parameters to achieve high throughput
    during heavy traffic and low latency during light traffic.
    rx_std_desc_cnt, (and rx_jumbo_desc_cnt if using jumbo frames) should not
    be set less than 50, and tx_pkt_desc_cnt should not be set less than 80
    when this parameter is enabled. Note that if the kernel supports the NAPI
    receive polling mode, interrupt coalescing will be handled in a different
    way and this parameter will not be used. The valid values are:

    0      disabled (always disabled in NAPI mode)
    1      enabled (default)

rx_coalesce_ticks

    Configures the number of 1 usec ticks before the NIC generates receive
    interrupt after receiving a frame. This parameter works in conjunction
    with the rx_max_coalesce_frames parameter. Interrupt will be generated
    when either of these thresholds is exceeded. 0 means this parameter is
    ignored and interrupt will be generated when the rx_max_coalesce_frames
    threshold is reached. The valid range is from 0 to 500, and default is
    60 (18 if using NAPI mode). This parameter is not used and will be
    adjusted automatically if adaptive_coalesce is set to 1.

rx_max_coalesce_frames

    Configures the number of received frames before the NIC generates receive
    interrupt. The valid range is from 0 to 100, and default is 15 (6 if using
    NAPI mode). This parameter and rx_coalesce_ticks cannot be both 0,
    otherwise no receive interrupts will be generated. It should also be set
    lower than rx_std_desc_cnt (and rx_jumbo_desc_cnt if using jumbo frames).
    This parameter is not used and will be adjusted automatically if
    adaptive_coalesce is set to 1.

tx_coalesce_ticks

    Configures the number of 1 usec ticks before the NIC generates transmit
    interrupt after transmitting a frame. This parameter works in conjunction
    with the tx_max_coalesce_frames parameter. Interrupt will be generated
    when either of these thresholds is exceeded. 0 means this
    parameter is ignored and interrupt will be generated when the
    tx_max_coalesce_frames threshold is reached. The valid range is from 0 to
    500, and default is 200. This parameter is not used and will be adjusted
    automatically if adaptive_coalesce is set to 1.

tx_max_coalesce_frames

    Configures the number of transmitted frames before the NIC generates
    transmit interrupt. The valid range is from 0 to 100, and default is 35.
    This parameter and tx_coalesce_ticks cannot be both 0, otherwise no
    transmit completion interrupt will be generated. This parameter should
    always be set lower than tx_pkt_desc_cnt. This parameter is not used and
    will be adjusted automatically if adaptive_coalesce is set to 1.

stats_coalesce_ticks

    Configures the number of 1 usec ticks between periodic statistics updates 
    (DMAs). The valid range is from 100 to 3600000000, and default is 1000000
    (1 sec.). 0 is also valid and is used to disable statistics updates.
    This parameter is not used and will be set to default if adaptive_coalesce
    is set to 1. Please note that the valid range may vary by kernel version.

enable_wol

    Enables or disables magic packet Wake-On-LAN when the system is shutdown.
    Note that not all systems support Wake-On-LAN. The valid values are:

    0    magic packet Wake-On-LAN disabled (default)
    1    magic packet Wake-On-LAN enabled

enable_tso

    Enables or disables TCP Segmentation Option (TSO) when using kernels that
    support it. This parameter is only defined on newer kernels that support
    TSO. The valid values are:

    0    TSO disabled
    1    TSO enabled (default)

disable_msi

    Enables or disables message signal interrupts (MSI) when using kernels that
    support it. This parameter is only defined on newer kernels that support
    MSI. The valid values are:

    1    MSI disabled
    0    MSI enabled (default)
    Note: Only applies to the latest devices.

vlan_tag_mode

    This parameter controls the stripping of VLAN tags on incoming packets,
    and is used to allow VLAN tagged ASF or IPMI packets to be received
    properly. The valid values are:

    0    Auto mode (default)
    1    Normal strip mode
    2    Forced strip mode

    In normal mode, VLAN tags are only stripped if VLANs are registered
    by the 802.1q VLAN module or BASP. In forced strip mode, VLAN tags
    are always stripped. Auto mode will select normal strip mode if ASF/IPMI
    is disabled, or forced strip mode if ASF/IPMI is enabled.

delay_link

    If set to 1, this parameter will cause the driver to return 
    -EOPNOTSUPP when the SIOCGMIIREG or ETHTOOL_GLINK ioctls are called
    during the first 6 seconds after driver reset. When the driver resets
    the NIC during ifconfig, the link will drop and it may take several
    seconds for the link to come up after autonegotiation completes. Some
    applications, such as ifup, may not wait long enough for the link
    before giving up. Setting this parameter to 1 may get around such
    problems. The default value is 0, which means that the driver will
    always return true link states to all ioctl calls, when applicable.

disable_d3hot

    If set to 1, this parameter will cause the driver to never
    put the device in D3Hot power state when the NIC is shutdown or
    suspended. If set, this parameter will also disable the Wake-On-Lan
    setting. A rare D3Hot related problem was seen during repeated
    shutdown of PCI Express devices on systems running 2.6 kernels.

Driver Messages
===============

The following are the most common sample messages that may be logged in the file
/var/log/messages. Use dmesg -n <level> to control the level at which messages
will appear on the console. Most systems are set to level 6 by default.

Broadcom Gigabit Ethernet Driver bcm5700 with Broadcom NIC Extension (NICE)
ver. 8.2.18 (08/01/05)

    Driver signon


eth#: Broadcom BCM5704 1000Base-T found at mem faff0000, IRQ 16, node addr
0010180402d8
eth#: Broadcom BCM5704 Integrated Copper transceiver found
eth#: Scatter-gather ON, 64-bit DMA ON, Tx Checksum ON, Rx Checksum ON, 802.1Q VLAN ON, TSO ON, NAPI ON

    NIC detected


bcm5700: eth# NIC Link is Up, 1000 Mbps full duplex, receive and transmit flow control ON

    Link up and speed indication


bcm5700: eth# NIC Link is Down

    Link down indication


Statistics
==========

Detailed statistics and configuration information can be viewed in the file
/proc/net/nicinfo/eth#.info.

