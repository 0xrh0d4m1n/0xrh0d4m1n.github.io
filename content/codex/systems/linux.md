---
title: "Linux"
tags:
  - systems
  - linux
---

# **LINUX**

<figure>
  <img src="/img/hero/5aeb4a0f6e453ce98b2506f3259f2fc4.jpeg" alt="Linux" style="width:100%;">
</figure>

The boot process on Linux is divided into four stages.

### **Bootstrap Phase**

This is the first stage where your machine comes to life from a state of complete inactivity.

#### BIOS (Basic Input/Output System)

1. **Power On**: You hit the power button, and your machine starts up. The CPU is activated and searches for the BIOS firmware instructions.
2. **POST (Power-On Self Test)**: The BIOS performs POST to check the hardware integrity like memory, keyboard, and other peripherals.
3. **BIOS Settings**: After POST, BIOS looks into its configured settings in the CMOS (Complementary Metal-Oxide-Semiconductor).
4. **Boot Device Selection**: BIOS checks the boot device order to find where the bootloader is. Typically, it could be a hard drive, CD/DVD, or USB drive.
5. **Bootloader Handoff**: Once the BIOS identifies the correct boot device with a valid bootloader, it hands over control to the bootloader's first stage (like GRUB or LILO).

---

#### UEFI (Unified Extensible Firmware Interface)

1. **Power On**: Similar to BIOS, the system is powered on and the CPU starts looking for instructions from the UEFI firmware.
2. **Self-tests and Initialization**: UEFI runs its own version of POST and initializes the hardware components.
3. **UEFI Boot Manager**: Unlike BIOS, UEFI comes with a boot manager which makes it easier to manage and select various boot devices.
4. **Boot Device Detection**: UEFI checks the list of boot devices stored in its NVRAM.
5. **EFI System Partition (ESP)**: UEFI looks for the EFI System Partition, which contains the bootloader files.
6. **Bootloader Execution**: After locating the correct ESP, UEFI executes the bootloader.

---

#### PXE (Preboot Execution Environment)

1. **Start-Up**: The machine is powered on, and the network card's PXE firmware kicks in.
2. **Network Initialization**: The network card initializes and sends out a broadcast request to find a PXE server.
3. **DHCP and IP Assignment**: A DHCP server assigns an IP address to the machine for network communication.
4. **Boot Server Contact**: The PXE-enabled network card contacts the boot server.
5. **Boot File Download**: The machine downloads the boot file via TFTP or other network protocols.
6. **Bootloader Transfer**: The downloaded file includes a bootloader that the machine then executes.

---

### **Bootloader Phase**

This is where the system prepares to launch the operating system.

#### GRUB (GNU GRand Unified Bootloader)

##### GRUB Stages

1. **Stage 1 (Primary Bootloader)**: Resides in the MBR. Its job is to load Stage 2 or 1.5.
2. **Stage 1.5 (Optional)**: Understands the filesystem and helps in loading Stage 2.
3. **Stage 2 (Secondary Bootloader)**: The core of GRUB. Presents the menu and loads the selected kernel into memory.

##### GRUB Menu

- **Menu Display**: Lists available kernels and operating systems defined in `grub.cfg`.
- **Selection**: Default set by timer or by manual selection.
- **Editing Options**: Press `e` to edit boot parameters on the fly.

##### GRUB Interactive Boot

- **Interactive Commands**: Press `c` at the GRUB menu to enter the GRUB command line.
- **Kernel Parameters**: Specify kernel parameters or boot to different runlevels.

---

#### LILO (Linux Loader)

- **Simpler Approach**: Older bootloader without GRUB's stages. Was popular before GRUB became standard.
- **Configuration**: Handled by `/etc/lilo.conf`. Must rerun the LILO command to apply changes.
- **No Interactive Mode**: Unlike GRUB, LILO does not have an interactive command-line mode.

---

### **Kernel Phase**

After being loaded by the bootloader, the kernel initializes the system.

#### Kernel Initialization

1. **Loading**: The kernel image is loaded into memory by the bootloader.
2. **Decompression**: The kernel decompresses itself.
3. **Hardware Detection**: The kernel detects the CPU, RAM, and other essential hardware.
4. **Initialization**: The kernel initializes the detected hardware and prepares drivers.
5. **Mount Root Filesystem**: The kernel mounts the root filesystem as read-only initially.
6. **Init Process**: The kernel starts the `init` process (PID 1), often `systemd`.

#### Kernel Boot Parameters

- **Passing Parameters**: The bootloader may pass parameters like root device, hardware options, or performance settings.
- **Runlevels**: The kernel can be instructed to boot into a specific runlevel.

---

### **Initialization Phase**

The final stretch before the system is ready for use.

#### System and Service Initialization

1. **Init Process**: `systemd` (or `Upstart`) is now fully in control.
2. **Runlevel/Target Services**: Networking, logging, graphical interfaces, etc. are started.
3. **Final System Configuration**: System-wide scripts are executed.
4. **Login Prompt**: The system displays a login prompt.

#### Key Tools: initrd, initramfs, and dracut

| Tool | Purpose |
|------|---------|
| **initrd** | Temporary root filesystem for initial boot (block device) |
| **mkinitrd** | Creates an initrd image |
| **initramfs** | Successor to initrd — a cpio archive filesystem |
| **mkinitramfs** | Creates an initramfs image |
| **dracut** | Modern, modular replacement for mkinitrd/mkinitramfs |

Each of these tools prepares a minimal environment that the kernel can use to get the system up and running before the actual root filesystem is available.
