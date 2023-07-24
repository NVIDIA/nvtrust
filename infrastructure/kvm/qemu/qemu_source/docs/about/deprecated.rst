.. _Deprecated features:

Deprecated features
===================

In general features are intended to be supported indefinitely once
introduced into QEMU. In the event that a feature needs to be removed,
it will be listed in this section. The feature will remain functional for the
release in which it was deprecated and one further release. After these two
releases, the feature is liable to be removed. Deprecated features may also
generate warnings on the console when QEMU starts up, or if activated via a
monitor command, however, this is not a mandatory requirement.

Prior to the 2.10.0 release there was no official policy on how
long features would be deprecated prior to their removal, nor
any documented list of which features were deprecated. Thus
any features deprecated prior to 2.10.0 will be treated as if
they were first deprecated in the 2.10.0 release.

What follows is a list of all features currently marked as
deprecated.

System emulator command line arguments
--------------------------------------

``QEMU_AUDIO_`` environment variables and ``-audio-help`` (since 4.0)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

The ``-audiodev`` argument is now the preferred way to specify audio
backend settings instead of environment variables.  To ease migration to
the new format, the ``-audiodev-help`` option can be used to convert
the current values of the environment variables to ``-audiodev`` options.

Creating sound card devices and vnc without ``audiodev=`` property (since 4.2)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

When not using the deprecated legacy audio config, each sound card
should specify an ``audiodev=`` property.  Additionally, when using
vnc, you should specify an ``audiodev=`` property if you plan to
transmit audio through the VNC protocol.

Creating sound card devices using ``-soundhw`` (since 5.1)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Sound card devices should be created using ``-device`` instead.  The
names are the same for most devices.  The exceptions are ``hda`` which
needs two devices (``-device intel-hda -device hda-duplex``) and
``pcspk`` which can be activated using ``-machine
pcspk-audiodev=<name>``.

``-chardev`` backend aliases ``tty`` and ``parport`` (since 6.0)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

``tty`` and ``parport`` are aliases that will be removed. Instead, the
actual backend names ``serial`` and ``parallel`` should be used.

Short-form boolean options (since 6.0)
''''''''''''''''''''''''''''''''''''''

Boolean options such as ``share=on``/``share=off`` could be written
in short form as ``share`` and ``noshare``.  This is now deprecated
and will cause a warning.

``delay`` option for socket character devices (since 6.0)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''

The replacement for the ``nodelay`` short-form boolean option is ``nodelay=on``
rather than ``delay=off``.

``--enable-fips`` (since 6.0)
'''''''''''''''''''''''''''''

This option restricts usage of certain cryptographic algorithms when
the host is operating in FIPS mode.

If FIPS compliance is required, QEMU should be built with the ``libgcrypt``
library enabled as a cryptography provider.

Neither the ``nettle`` library, or the built-in cryptography provider are
supported on FIPS enabled hosts.

``-writeconfig`` (since 6.0)
'''''''''''''''''''''''''''''

The ``-writeconfig`` option is not able to serialize the entire contents
of the QEMU command line.  It is thus considered a failed experiment
and deprecated, with no current replacement.

Userspace local APIC with KVM (x86, since 6.0)
''''''''''''''''''''''''''''''''''''''''''''''

Using ``-M kernel-irqchip=off`` with x86 machine types that include a local
APIC is deprecated.  The ``split`` setting is supported, as is using
``-M kernel-irqchip=off`` with the ISA PC machine type.

hexadecimal sizes with scaling multipliers (since 6.0)
''''''''''''''''''''''''''''''''''''''''''''''''''''''

Input parameters that take a size value should only use a size suffix
(such as 'k' or 'M') when the base is written in decimal, and not when
the value is hexadecimal.  That is, '0x20M' is deprecated, and should
be written either as '32M' or as '0x2000000'.

``-spice password=string`` (since 6.0)
''''''''''''''''''''''''''''''''''''''

This option is insecure because the SPICE password remains visible in
the process listing. This is replaced by the new ``password-secret``
option which lets the password be securely provided on the command
line using a ``secret`` object instance.

``opened`` property of ``rng-*`` objects (since 6.0)
''''''''''''''''''''''''''''''''''''''''''''''''''''

The only effect of specifying ``opened=on`` in the command line or QMP
``object-add`` is that the device is opened immediately, possibly before all
other options have been processed.  This will either have no effect (if
``opened`` was the last option) or cause errors.  The property is therefore
useless and should not be specified.

``loaded`` property of ``secret`` and ``secret_keyring`` objects (since 6.0)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

The only effect of specifying ``loaded=on`` in the command line or QMP
``object-add`` is that the secret is loaded immediately, possibly before all
other options have been processed.  This will either have no effect (if
``loaded`` was the last option) or cause options to be effectively ignored as
if they were not given.  The property is therefore useless and should not be
specified.

``-display sdl,window_close=...`` (since 6.1)
'''''''''''''''''''''''''''''''''''''''''''''

Use ``-display sdl,window-close=...`` instead (i.e. with a minus instead of
an underscore between "window" and "close").

``-no-quit`` (since 6.1)
''''''''''''''''''''''''

The ``-no-quit`` is a synonym for ``-display ...,window-close=off`` which
should be used instead.

``-alt-grab`` and ``-display sdl,alt_grab=on`` (since 6.2)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Use ``-display sdl,grab-mod=lshift-lctrl-lalt`` instead.

``-ctrl-grab`` and ``-display sdl,ctrl_grab=on`` (since 6.2)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Use ``-display sdl,grab-mod=rctrl`` instead.

``-sdl`` (since 6.2)
''''''''''''''''''''

Use ``-display sdl`` instead.

``-curses`` (since 6.2)
'''''''''''''''''''''''

Use ``-display curses`` instead.

``-smp`` ("parameter=0" SMP configurations) (since 6.2)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''

Specified CPU topology parameters must be greater than zero.

In the SMP configuration, users should either provide a CPU topology
parameter with a reasonable value (greater than zero) or just omit it
and QEMU will compute the missing value.

However, historically it was implicitly allowed for users to provide
a parameter with zero value, which is meaningless and could also possibly
cause unexpected results in the -smp parsing. So support for this kind of
configurations (e.g. -smp 8,sockets=0) is deprecated since 6.2 and will
be removed in the near future, users have to ensure that all the topology
members described with -smp are greater than zero.

Plugin argument passing through ``arg=<string>`` (since 6.1)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Passing TCG plugins arguments through ``arg=`` is redundant is makes the
command-line less readable, especially when the argument itself consist of a
name and a value, e.g. ``-plugin plugin_name,arg="arg_name=arg_value"``.
Therefore, the usage of ``arg`` is redundant. Single-word arguments are treated
as short-form boolean values, and passed to plugins as ``arg_name=on``.
However, short-form booleans are deprecated and full explicit ``arg_name=on``
form is preferred.


QEMU Machine Protocol (QMP) commands
------------------------------------

``blockdev-open-tray``, ``blockdev-close-tray`` argument ``device`` (since 2.8)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Use argument ``id`` instead.

``eject`` argument ``device`` (since 2.8)
'''''''''''''''''''''''''''''''''''''''''

Use argument ``id`` instead.

``blockdev-change-medium`` argument ``device`` (since 2.8)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Use argument ``id`` instead.

``block_set_io_throttle`` argument ``device`` (since 2.8)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Use argument ``id`` instead.

``blockdev-add`` empty string argument ``backing`` (since 2.10)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Use argument value ``null`` instead.

``block-commit`` arguments ``base`` and ``top`` (since 3.1)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Use arguments ``base-node`` and ``top-node`` instead.

``nbd-server-add`` and ``nbd-server-remove`` (since 5.2)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Use the more generic commands ``block-export-add`` and ``block-export-del``
instead.  As part of this deprecation, where ``nbd-server-add`` used a
single ``bitmap``, the new ``block-export-add`` uses a list of ``bitmaps``.

System accelerators
-------------------

MIPS ``Trap-and-Emul`` KVM support (since 6.0)
''''''''''''''''''''''''''''''''''''''''''''''

The MIPS ``Trap-and-Emul`` KVM host and guest support has been removed
from Linux upstream kernel, declare it deprecated.

System emulator CPUS
--------------------

``Icelake-Client`` CPU Model (since 5.2)
''''''''''''''''''''''''''''''''''''''''

``Icelake-Client`` CPU Models are deprecated. Use ``Icelake-Server`` CPU
Models instead.

MIPS ``I7200`` CPU Model (since 5.2)
''''''''''''''''''''''''''''''''''''

The ``I7200`` guest CPU relies on the nanoMIPS ISA, which is deprecated
(the ISA has never been upstreamed to a compiler toolchain). Therefore
this CPU is also deprecated.


QEMU API (QAPI) events
----------------------

``MEM_UNPLUG_ERROR`` (since 6.2)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Use the more generic event ``DEVICE_UNPLUG_GUEST_ERROR`` instead.


System emulator machines
------------------------

Aspeed ``swift-bmc`` machine (since 6.1)
''''''''''''''''''''''''''''''''''''''''

This machine is deprecated because we have enough AST2500 based OpenPOWER
machines. It can be easily replaced by the ``witherspoon-bmc`` or the
``romulus-bmc`` machines.

Backend options
---------------

Using non-persistent backing file with pmem=on (since 6.1)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

This option is used when ``memory-backend-file`` is consumed by emulated NVDIMM
device. However enabling ``memory-backend-file.pmem`` option, when backing file
is (a) not DAX capable or (b) not on a filesystem that support direct mapping
of persistent memory, is not safe and may lead to data loss or corruption in case
of host crash.
Options are:

    - modify VM configuration to set ``pmem=off`` to continue using fake NVDIMM
      (without persistence guaranties) with backing file on non DAX storage
    - move backing file to NVDIMM storage and keep ``pmem=on``
      (to have NVDIMM with persistence guaranties).

Device options
--------------

Emulated device options
'''''''''''''''''''''''

``-device virtio-blk,scsi=on|off`` (since 5.0)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The virtio-blk SCSI passthrough feature is a legacy VIRTIO feature.  VIRTIO 1.0
and later do not support it because the virtio-scsi device was introduced for
full SCSI support.  Use virtio-scsi instead when SCSI passthrough is required.

Note this also applies to ``-device virtio-blk-pci,scsi=on|off``, which is an
alias.

Block device options
''''''''''''''''''''

``"backing": ""`` (since 2.12)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In order to prevent QEMU from automatically opening an image's backing
chain, use ``"backing": null`` instead.

``rbd`` keyvalue pair encoded filenames: ``""`` (since 3.1)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Options for ``rbd`` should be specified according to its runtime options,
like other block drivers.  Legacy parsing of keyvalue pair encoded
filenames is useful to open images with the old format for backing files;
These image files should be updated to use the current format.

Example of legacy encoding::

  json:{"file.driver":"rbd", "file.filename":"rbd:rbd/name"}

The above, converted to the current supported format::

  json:{"file.driver":"rbd", "file.pool":"rbd", "file.image":"name"}

linux-user mode CPUs
--------------------

``ppc64abi32`` CPUs (since 5.2)
'''''''''''''''''''''''''''''''

The ``ppc64abi32`` architecture has a number of issues which regularly
trip up our CI testing and is suspected to be quite broken. For that
reason the maintainers strongly suspect no one actually uses it.

MIPS ``I7200`` CPU (since 5.2)
''''''''''''''''''''''''''''''

The ``I7200`` guest CPU relies on the nanoMIPS ISA, which is deprecated
(the ISA has never been upstreamed to a compiler toolchain). Therefore
this CPU is also deprecated.

Related binaries
----------------

Backwards compatibility
-----------------------

Runnability guarantee of CPU models (since 4.1)
'''''''''''''''''''''''''''''''''''''''''''''''

Previous versions of QEMU never changed existing CPU models in
ways that introduced additional host software or hardware
requirements to the VM.  This allowed management software to
safely change the machine type of an existing VM without
introducing new requirements ("runnability guarantee").  This
prevented CPU models from being updated to include CPU
vulnerability mitigations, leaving guests vulnerable in the
default configuration.

The CPU model runnability guarantee won't apply anymore to
existing CPU models.  Management software that needs runnability
guarantees must resolve the CPU model aliases using the
``alias-of`` field returned by the ``query-cpu-definitions`` QMP
command.

While those guarantees are kept, the return value of
``query-cpu-definitions`` will have existing CPU model aliases
point to a version that doesn't break runnability guarantees
(specifically, version 1 of those CPU models).  In future QEMU
versions, aliases will point to newer CPU model versions
depending on the machine type, so management software must
resolve CPU model aliases before starting a virtual machine.

Guest Emulator ISAs
-------------------

nanoMIPS ISA
''''''''''''

The ``nanoMIPS`` ISA has never been upstreamed to any compiler toolchain.
As it is hard to generate binaries for it, declare it deprecated.
